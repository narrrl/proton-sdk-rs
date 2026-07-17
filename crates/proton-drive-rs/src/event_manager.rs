//! Managed Drive event polling.
//!
//! A background loop that drains a volume's event cursor, invalidates the
//! client's caches, persists the cursor, and fans each event out to
//! subscribers. Mirrors the TS `internal/events` stack (`eventManager` +
//! `eventScheduler`): a per-scope poll loop at a foreground/background interval,
//! event→cache invalidation, and a subscription API.
//!
//! Before this, every consumer rolled its own loop (the `proton-drive-linux`
//! FUSE daemon has one) and none invalidated the client's own `folder_keys` /
//! entity cache — the staleness SDK plan #9 describes. Routing events through an
//! [`EventManager`] closes that gap: [`ProtonDriveClient::invalidate_caches_for_event`]
//! runs for every event before it reaches subscribers, so the SDK's caches
//! converge on the server without each consumer re-implementing it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use proton_sdk::error::Result;
use proton_sdk::ids::DriveEventId;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::client::ProtonDriveClient;
use crate::events::{DriveEvent, DriveEventScopeId};

/// Foreground poll interval — the scope is actively in use. Matches TS
/// `FOREGROUND_POLLING_INTERVAL_SECONDS` (30s).
pub const DEFAULT_FOREGROUND_INTERVAL: Duration = Duration::from_secs(30);

/// Background poll interval — the scope is idle. Matches TS
/// `BACKGROUND_POLLING_INTERVAL_SECONDS` (10 min).
pub const DEFAULT_BACKGROUND_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Smallest wait before retrying a failed poll, doubled on each consecutive
/// failure up to the current poll interval.
const RETRY_MIN: Duration = Duration::from_secs(1);

/// Persistence for the enumeration cursor.
///
/// The SDK owns no storage, so a consumer supplies one: a daemon persists to
/// disk (the FUSE daemon uses SQLite) so a restart *resumes* from where it left
/// off rather than reseeding from the server head — reseeding would silently
/// skip everything that changed while the process was stopped.
#[async_trait]
pub trait CursorStore: Send + Sync {
    /// The last persisted cursor, or `None` for a first-ever run.
    async fn load(&self) -> Result<Option<DriveEventId>>;
    /// Persist `cursor` as the resume point for the next run.
    async fn save(&self, cursor: &DriveEventId) -> Result<()>;
}

/// In-memory [`CursorStore`]. Loses the cursor when dropped, so a process using
/// it reseeds from the server head on each start. Fine for tests and one-shot
/// consumers; a long-running daemon wants a persistent store instead.
#[derive(Default)]
pub struct MemoryCursorStore {
    cursor: tokio::sync::Mutex<Option<DriveEventId>>,
}

#[async_trait]
impl CursorStore for MemoryCursorStore {
    async fn load(&self) -> Result<Option<DriveEventId>> {
        Ok(self.cursor.lock().await.clone())
    }
    async fn save(&self, cursor: &DriveEventId) -> Result<()> {
        *self.cursor.lock().await = Some(cursor.clone());
        Ok(())
    }
}

/// Tuning for an [`EventManager`].
#[derive(Debug, Clone)]
pub struct EventManagerConfig {
    /// Poll interval while the scope is in the foreground.
    pub foreground_interval: Duration,
    /// Poll interval while the scope is in the background.
    pub background_interval: Duration,
    /// Broadcast buffer size. A subscriber that falls this far behind receives a
    /// [`broadcast::error::RecvError::Lagged`] and should treat it like a
    /// continuity loss — resync from current server state.
    pub channel_capacity: usize,
}

impl Default for EventManagerConfig {
    fn default() -> Self {
        Self {
            foreground_interval: DEFAULT_FOREGROUND_INTERVAL,
            background_interval: DEFAULT_BACKGROUND_INTERVAL,
            channel_capacity: 256,
        }
    }
}

/// Polls one event scope, invalidates the client's caches, and publishes events
/// to subscribers.
///
/// Single-scope by design (the volume the caller cares about — typically their
/// own My Files volume). A caller that tracks several scopes runs one manager
/// each; the foreground/background switch then lets a shared scope poll lazily
/// until the user opens it.
pub struct EventManager {
    client: ProtonDriveClient,
    scope: DriveEventScopeId,
    store: Arc<dyn CursorStore>,
    config: EventManagerConfig,
    events_tx: broadcast::Sender<DriveEvent>,
    foreground: Arc<AtomicBool>,
}

impl EventManager {
    /// Build a manager for `scope`, persisting its cursor through `store`, with
    /// default intervals. Starts in the foreground.
    pub fn new(
        client: ProtonDriveClient,
        scope: DriveEventScopeId,
        store: Arc<dyn CursorStore>,
    ) -> Self {
        Self::with_config(client, scope, store, EventManagerConfig::default())
    }

    /// As [`new`](Self::new), with explicit tuning.
    pub fn with_config(
        client: ProtonDriveClient,
        scope: DriveEventScopeId,
        store: Arc<dyn CursorStore>,
        config: EventManagerConfig,
    ) -> Self {
        let (events_tx, _) = broadcast::channel(config.channel_capacity.max(1));
        Self {
            client,
            scope,
            store,
            config,
            events_tx,
            foreground: Arc::new(AtomicBool::new(true)),
        }
    }

    /// A receiver for the event feed. Each subscriber sees every event applied
    /// after it subscribed. Cache invalidation already happened in the manager,
    /// so a subscriber only needs to update *its own* state (e.g. a UI or FUSE
    /// tree).
    pub fn subscribe(&self) -> broadcast::Receiver<DriveEvent> {
        self.events_tx.subscribe()
    }

    /// Switch the scope between the foreground (frequent) and background (lazy)
    /// poll interval. Takes effect on the next poll cycle.
    pub fn set_foreground(&self, foreground: bool) {
        self.foreground.store(foreground, Ordering::Relaxed);
    }

    /// Whether the scope is currently polled at the foreground interval.
    pub fn is_foreground(&self) -> bool {
        self.foreground.load(Ordering::Relaxed)
    }

    fn current_interval(&self) -> Duration {
        if self.is_foreground() {
            self.config.foreground_interval
        } else {
            self.config.background_interval
        }
    }

    /// Load the resume cursor, seeding from the server head on a first-ever run.
    ///
    /// Seeding needs the network and a manager may start while offline, so a
    /// seed failure is retried with backoff rather than giving up (which would
    /// disable sync for the life of the process). A persisted cursor resumes
    /// immediately without a network call.
    async fn resolve_start_cursor(&self) -> Option<DriveEventId> {
        match self.store.load().await {
            Ok(Some(cursor)) => return Some(cursor),
            Ok(None) => {}
            Err(e) => warn!(error = %e, "load event cursor failed; seeding from head"),
        }

        let mut delay = RETRY_MIN;
        loop {
            match self.client.enumerate_events(&self.scope, None).await {
                Ok(events) => {
                    let head = events.last().map(|e| e.id().clone());
                    if let Some(cursor) = &head
                        && let Err(e) = self.store.save(cursor).await
                    {
                        warn!(error = %e, "persist seed cursor failed");
                    }
                    return head;
                }
                Err(e) => {
                    warn!(error = %e, ?delay, "seed event cursor failed; retrying");
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(self.config.background_interval);
                }
            }
        }
    }

    /// Poll the scope forever: at each interval, drain events from the cursor,
    /// invalidate the client's caches, publish each event, and persist the new
    /// cursor. Returns only if the cursor cannot be resolved at all.
    ///
    /// Runs as a task; hold the manager in an `Arc` and spawn a clone:
    /// `let m = mgr.clone(); tokio::spawn(async move { m.run().await });`.
    pub async fn run(&self) {
        let mut cursor = self.resolve_start_cursor().await;
        info!(scope = %self.scope, ?cursor, "event manager started");

        let mut retry = RETRY_MIN;
        loop {
            tokio::time::sleep(self.current_interval()).await;

            let events = match self
                .client
                .enumerate_events(&self.scope, cursor.as_ref())
                .await
            {
                Ok(events) => events,
                Err(e) => {
                    warn!(error = %e, ?retry, "event poll failed; backing off");
                    tokio::time::sleep(retry).await;
                    retry = (retry * 2).min(self.current_interval());
                    continue;
                }
            };
            retry = RETRY_MIN;

            if events.is_empty() {
                continue;
            }
            debug!(count = events.len(), "applying remote events");
            for event in &events {
                if let Err(e) = self.client.invalidate_caches_for_event(event).await {
                    warn!(error = %e, "cache invalidation for event failed");
                }
                // A send with no live receivers returns Err; that is normal (the
                // cache invalidation above is the load-bearing effect), so ignore
                // it rather than treat "nobody is listening" as a failure.
                let _ = self.events_tx.send(event.clone());
            }

            cursor = events.last().map(|e| e.id().clone());
            if let Some(cursor) = &cursor
                && let Err(e) = self.store.save(cursor).await
            {
                warn!(error = %e, "persist event cursor failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_cursor_store_roundtrips() {
        let store = MemoryCursorStore::default();
        assert!(store.load().await.unwrap().is_none());

        let id = DriveEventId::new("evt-42");
        store.save(&id).await.unwrap();
        assert_eq!(store.load().await.unwrap(), Some(id));
    }

    #[test]
    fn config_defaults_match_ts_scheduler() {
        let config = EventManagerConfig::default();
        assert_eq!(config.foreground_interval, Duration::from_secs(30));
        assert_eq!(config.background_interval, Duration::from_secs(600));
        assert!(config.channel_capacity > 0);
    }
}
