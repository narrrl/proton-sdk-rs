//! Collapse concurrent identical loads into one request.
//!
//! Mirrors the intent of the TypeScript SDK's `internal/nodes/debouncer.ts` and
//! `internal/batchLoading.ts`: several callers asking for the same node — or the
//! same folder's key — at the same moment should cost one round-trip and one
//! decrypt, not one each. The batching half of those modules has no counterpart
//! here; this crate's loads are already issued in batches.

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;

use futures::future::{BoxFuture, FutureExt, Shared};
use proton_sdk::error::{ProtonError, Result};
use tokio::sync::Mutex;

type SharedLoad<V> = Shared<BoxFuture<'static, std::result::Result<V, Arc<ProtonError>>>>;

/// A set of in-flight loads keyed by what they load.
pub(crate) struct SingleFlight<K, V> {
    inflight: Mutex<HashMap<K, SharedLoad<V>>>,
}

impl<K, V> Default for SingleFlight<K, V> {
    fn default() -> Self {
        Self {
            inflight: Mutex::new(HashMap::new()),
        }
    }
}

impl<K, V> SingleFlight<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone + Send + 'static,
{
    /// Run `load` for `key`, or join the one already running for it.
    ///
    /// `load` must be self-contained (`'static`) because the caller that starts
    /// it may go away before it finishes, leaving another to drive it.
    ///
    /// **Errors are shared, and sharing costs type fidelity.** [`ProtonError`]
    /// is not `Clone` (its `Transport` variant wraps a `reqwest::Error`), so a
    /// failed load hands every waiter — the one that started it included — a
    /// rebuilt error: an API failure keeps its full [`ProtonApiError`], and
    /// everything else degrades to
    /// [`ProtonError::InvalidOperation`](proton_sdk::error::ProtonError::InvalidOperation)
    /// carrying the original message. Callers that match on `ResponseCode` are
    /// therefore unaffected; callers that match on the *variant* of a transport
    /// failure would be, and none do.
    pub(crate) async fn run<F>(&self, key: K, load: F) -> Result<V>
    where
        F: Future<Output = Result<V>> + Send + 'static,
    {
        let shared = {
            let mut inflight = self.inflight.lock().await;
            match inflight.get(&key) {
                Some(existing) => existing.clone(),
                None => {
                    let load = load
                        .map(|outcome| outcome.map_err(Arc::new))
                        .boxed()
                        .shared();
                    inflight.insert(key.clone(), load.clone());
                    load
                }
            }
        };

        let outcome = shared.await;

        // Clear the slot so the *next* caller gets a fresh load rather than this
        // one's result. A racing arrival that already cloned the handle still
        // gets this result, which is the point.
        self.inflight.lock().await.remove(&key);

        outcome.map_err(|error| match error.as_ref() {
            ProtonError::Api(e) => ProtonError::Api(e.clone()),
            other => ProtonError::invalid_operation(other.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proton_sdk::api::ResponseCode;
    use proton_sdk::error::ProtonApiError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    #[tokio::test]
    async fn concurrent_loads_of_the_same_key_run_once() {
        let flight: SingleFlight<&'static str, usize> = SingleFlight::default();
        let runs = Arc::new(AtomicUsize::new(0));

        // The gate holds the load open until every waiter has registered — the
        // case single-flighting exists for. A `Notify` rather than a one-shot so
        // that a *failure* to deduplicate shows up as a wrong count, not a hang.
        let gate = Arc::new(Notify::new());
        let waiters = (0..8).map(|_| {
            let runs = runs.clone();
            let gate = gate.clone();
            flight.run("node", async move {
                gate.notified().await;
                Ok(runs.fetch_add(1, Ordering::SeqCst))
            })
        });

        let (outcomes, ()) = tokio::join!(futures::future::join_all(waiters), async {
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            gate.notify_waiters();
        });

        for outcome in outcomes {
            assert_eq!(outcome.expect("load"), 0);
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_later_load_is_not_served_the_previous_result() {
        let flight: SingleFlight<&'static str, usize> = SingleFlight::default();
        assert_eq!(flight.run("node", async { Ok(1) }).await.expect("first"), 1);
        assert_eq!(
            flight.run("node", async { Ok(2) }).await.expect("second"),
            2
        );
    }

    #[tokio::test]
    async fn a_shared_api_failure_keeps_its_response_code() {
        let flight: SingleFlight<&'static str, usize> = SingleFlight::default();
        let error = flight
            .run("node", async {
                Err(ProtonError::Api(ProtonApiError {
                    code: ResponseCode::DoesNotExist,
                    http_status: 422,
                    message: "gone".into(),
                    details: None,
                }))
            })
            .await
            .expect_err("load fails");

        match error {
            ProtonError::Api(e) => {
                assert!(matches!(e.code, ResponseCode::DoesNotExist));
                assert_eq!(e.http_status, 422);
                assert_eq!(e.message, "gone");
            }
            other => panic!("expected an api error, got {other}"),
        }
    }
}
