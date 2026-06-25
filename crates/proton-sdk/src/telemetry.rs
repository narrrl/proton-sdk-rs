//! Pluggable telemetry / structured-observability hooks.
//!
//! The SDK records a [`TelemetryEvent`] for each instrumented operation
//! (transfers, navigation, API calls) and hands it to a consumer-supplied
//! [`Telemetry`] observer. This mirrors the C# `Proton.Sdk` telemetry layer's
//! `ITelemetry`-style sink: the SDK measures, the host decides what to do with
//! the measurements (export to metrics, log, drop).
//!
//! Observers are **fire-and-forget and must not block**: [`Telemetry::record`]
//! is called on the SDK's own task, synchronously, often inside a hot path. Do
//! cheap work (increment a counter, enqueue) and return; offload anything
//! heavy.
//!
//! Two built-ins are provided: [`NoopTelemetry`] (the default — records
//! nothing) and [`TracingTelemetry`] (forwards every event to the `tracing`
//! crate, tying telemetry into the SDK's existing structured logging).

use std::sync::Arc;
use std::time::Duration;

/// The outcome of an instrumented operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The operation completed successfully.
    Success,
    /// The operation returned an error (or was dropped before being marked
    /// successful — see [`OpTimer`]).
    Failure,
}

impl Outcome {
    /// `"success"` / `"failure"` — the label form used by [`TracingTelemetry`]
    /// and convenient for metric dimensions.
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
        }
    }
}

/// A single measurement emitted by the SDK for one instrumented operation.
///
/// `operation` is a stable, low-cardinality identifier (e.g. `"download_file"`,
/// `"upload_file"`, `"enumerate_folder_children"`) safe to use as a metric name
/// or dimension. `attributes` carry extra low-cardinality context (e.g.
/// `("block_count", "12")`); avoid per-request unique values (ids, names) that
/// would explode a metrics backend's cardinality.
#[derive(Debug, Clone)]
pub struct TelemetryEvent {
    /// Stable operation identifier.
    pub operation: &'static str,
    /// Whether the operation succeeded.
    pub outcome: Outcome,
    /// Wall-clock time the operation took.
    pub duration: Duration,
    /// Extra low-cardinality key/value context.
    pub attributes: Vec<(&'static str, String)>,
}

/// A consumer-supplied sink for [`TelemetryEvent`]s.
///
/// Mirrors the C# telemetry sink. Implementations must be cheap to share across
/// tasks (hence [`Send`] + [`Sync`]); the SDK holds them as
/// `Arc<dyn Telemetry>`. [`record`](Telemetry::record) must not block.
pub trait Telemetry: Send + Sync {
    /// Receive one measurement. Called synchronously on the SDK's task.
    fn record(&self, event: &TelemetryEvent);
}

/// The default observer: records nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopTelemetry;

impl Telemetry for NoopTelemetry {
    fn record(&self, _event: &TelemetryEvent) {}
}

impl NoopTelemetry {
    /// A shared no-op observer, for use as the default telemetry sink.
    pub fn shared() -> Arc<dyn Telemetry> {
        Arc::new(NoopTelemetry)
    }
}

/// An observer that forwards every event to the `tracing` crate.
///
/// Successful operations emit at `debug`, failures at `warn`, both on the
/// `proton_sdk::telemetry` target with structured `operation`, `outcome`,
/// `duration_ms` and the event's attributes flattened into the message. This
/// bridges telemetry into the SDK's existing `tracing`-based logging without a
/// separate metrics backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingTelemetry;

impl TracingTelemetry {
    /// A shared `tracing`-forwarding observer.
    pub fn shared() -> Arc<dyn Telemetry> {
        Arc::new(TracingTelemetry)
    }
}

impl Telemetry for TracingTelemetry {
    fn record(&self, event: &TelemetryEvent) {
        let duration_ms = event.duration.as_secs_f64() * 1000.0;
        // Attributes are flattened into a single string so the log line stays
        // readable regardless of how many there are.
        let attrs = event
            .attributes
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        match event.outcome {
            Outcome::Success => tracing::debug!(
                target: "proton_sdk::telemetry",
                operation = event.operation,
                outcome = event.outcome.as_str(),
                duration_ms,
                attributes = %attrs,
                "operation completed",
            ),
            Outcome::Failure => tracing::warn!(
                target: "proton_sdk::telemetry",
                operation = event.operation,
                outcome = event.outcome.as_str(),
                duration_ms,
                attributes = %attrs,
                "operation failed",
            ),
        }
    }
}

/// A scoped timer that records a [`TelemetryEvent`] when dropped.
///
/// Construct one at the start of an operation via [`Telemetry`]'s
/// [`start`](TelemetryExt::start) helper. It defaults to [`Outcome::Failure`]
/// so an early `?`-return is recorded as a failure automatically; call
/// [`success`](OpTimer::success) on the happy path before returning. Attach
/// extra context with [`attr`](OpTimer::attr).
///
/// ```ignore
/// let mut timer = telemetry.start("download_file");
/// let blocks = fetch_blocks().await?;        // early return => Failure
/// timer.attr("block_count", blocks.len());
/// timer.success();                            // mark before Ok
/// Ok(data)
/// ```
pub struct OpTimer {
    telemetry: Arc<dyn Telemetry>,
    operation: &'static str,
    start: std::time::Instant,
    outcome: Outcome,
    attributes: Vec<(&'static str, String)>,
}

impl OpTimer {
    /// Mark the operation successful. Without this, drop records a failure.
    pub fn success(&mut self) {
        self.outcome = Outcome::Success;
    }

    /// Explicitly set the outcome (rarely needed; prefer [`success`](Self::success)).
    pub fn set_outcome(&mut self, outcome: Outcome) {
        self.outcome = outcome;
    }

    /// Attach a low-cardinality attribute to the event recorded on drop.
    pub fn attr(&mut self, key: &'static str, value: impl ToString) {
        self.attributes.push((key, value.to_string()));
    }
}

impl Drop for OpTimer {
    fn drop(&mut self) {
        let event = TelemetryEvent {
            operation: self.operation,
            outcome: self.outcome,
            duration: self.start.elapsed(),
            // Take the attributes out so we don't clone; `self` is being dropped.
            attributes: std::mem::take(&mut self.attributes),
        };
        self.telemetry.record(&event);
    }
}

/// Ergonomic entry point for instrumenting an operation against a shared
/// telemetry sink.
pub trait TelemetryExt {
    /// Begin timing `operation`, returning an [`OpTimer`] that records on drop.
    fn start(&self, operation: &'static str) -> OpTimer;
}

impl TelemetryExt for Arc<dyn Telemetry> {
    fn start(&self, operation: &'static str) -> OpTimer {
        OpTimer {
            telemetry: Arc::clone(self),
            operation,
            start: std::time::Instant::now(),
            outcome: Outcome::Failure,
            attributes: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A test sink that captures every recorded event.
    #[derive(Default)]
    struct Capture(Mutex<Vec<TelemetryEvent>>);

    impl Telemetry for Capture {
        fn record(&self, event: &TelemetryEvent) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    fn shared_capture() -> (Arc<dyn Telemetry>, Arc<Capture>) {
        let capture = Arc::new(Capture::default());
        (capture.clone() as Arc<dyn Telemetry>, capture)
    }

    #[test]
    fn timer_records_failure_by_default() {
        let (sink, capture) = shared_capture();
        {
            let _timer = sink.start("op_a");
            // dropped without success()
        }
        let events = capture.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, "op_a");
        assert_eq!(events[0].outcome, Outcome::Failure);
    }

    #[test]
    fn timer_records_success_and_attributes() {
        let (sink, capture) = shared_capture();
        {
            let mut timer = sink.start("op_b");
            timer.attr("block_count", 3usize);
            timer.success();
        }
        let events = capture.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, Outcome::Success);
        assert_eq!(events[0].attributes, vec![("block_count", "3".to_string())]);
    }

    #[test]
    fn noop_records_nothing() {
        let sink = NoopTelemetry::shared();
        let mut timer = sink.start("op_c");
        timer.success();
        // No panic, nothing to assert — the point is it compiles and runs.
    }

    #[test]
    fn outcome_label_form() {
        assert_eq!(Outcome::Success.as_str(), "success");
        assert_eq!(Outcome::Failure.as_str(), "failure");
    }
}
