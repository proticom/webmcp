//! Config hot-reload: while `webmcp connect` runs, `attach` and `detach`
//! edit `config.toml` and the running daemon follows along.
//!
//! No file-watcher dependency: the file's mtime and length are polled. The
//! [`ConfigWatcher`] is owned by the reconnect loop, so the attached set it
//! holds outlives any one connection and is the source of truth for what a
//! reconnect advertises.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ed25519_dalek::VerifyingKey;
use tokio::time::{Interval, MissedTickBehavior};
use tracing::{debug, info, warn};

use crate::config::{Config, ServerEntry};
use crate::keys;
use crate::proto::ServerInfo;

/// How often the config file is checked unless the caller says otherwise.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// What `stat` said about the config file the last time it was looked at.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Stamp {
    Missing,
    File {
        modified: Option<SystemTime>,
        len: u64,
    },
}

impl Stamp {
    fn of(path: &Path) -> Stamp {
        match std::fs::metadata(path) {
            Ok(meta) => Stamp::File {
                modified: meta.modified().ok(),
                len: meta.len(),
            },
            Err(_) => Stamp::Missing,
        }
    }
}

/// The pairing identity the running daemon was started with. It is never
/// hot-reloaded; a config that disagrees only earns a warning.
#[derive(Debug, Clone)]
pub struct Pairing {
    pub device_id: String,
    pub relay_url: String,
    pub verifying_key: VerifyingKey,
}

/// The current attached set, refreshed from the config file on a poll.
pub struct ConfigWatcher {
    /// `None` disables reloading: the set stays what it was seeded with.
    path: Option<PathBuf>,
    pairing: Pairing,
    ticker: Interval,
    /// `None` until the file was looked at once.
    last: Option<Stamp>,
    /// The last look failed; parse again even if the stamp did not move.
    retry: bool,
    entries: Vec<ServerEntry>,
    infos: Vec<ServerInfo>,
}

impl ConfigWatcher {
    /// Seed with the startup set. `infos` is what gets advertised until a
    /// reload replaces it (tests advertise sets with no backends behind
    /// them).
    pub fn new(
        path: Option<PathBuf>,
        interval: Duration,
        pairing: Pairing,
        entries: Vec<ServerEntry>,
        infos: Vec<ServerInfo>,
    ) -> Self {
        let mut ticker = tokio::time::interval(interval.max(Duration::from_millis(1)));
        // Ticks pile up while the daemon is between connections.
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ConfigWatcher {
            path,
            pairing,
            ticker,
            last: None,
            retry: false,
            entries,
            infos,
        }
    }

    /// The servers relayed right now.
    pub fn entries(&self) -> &[ServerEntry] {
        &self.entries
    }

    /// The `servers` frame payload for the current set.
    pub fn infos(&self) -> &[ServerInfo] {
        &self.infos
    }

    /// Resolves the next time the attached set changes; never when
    /// reloading is disabled. Cancel safe: a change is recorded in `self`
    /// in the same step that detects it, never across an await.
    pub async fn changed(&mut self) {
        if self.path.is_none() {
            return std::future::pending().await;
        }
        loop {
            self.ticker.tick().await;
            if self.poll() {
                return;
            }
        }
    }

    /// Look at the file once. True when the attached set changed. The file
    /// is small and local, so this reads it on the calling task.
    pub fn poll(&mut self) -> bool {
        let Some(path) = self.path.as_deref() else {
            return false;
        };
        let stamp = Stamp::of(path);
        let moved = self.last != Some(stamp);
        if !moved && !self.retry {
            return false;
        }
        self.last = Some(stamp);
        let cfg = match Config::load_path(path) {
            Ok(cfg) => cfg,
            Err(e) => {
                // Mid-write or hand-edited into a corner. Keep serving the
                // current set and look again next tick; warn once per
                // version of the file.
                if moved {
                    warn!(error = %e, "config changed but could not be loaded; keeping the current servers");
                } else {
                    debug!(error = %e, "config still not loadable");
                }
                self.retry = true;
                return false;
            }
        };
        self.retry = false;
        self.check_pairing(path, &cfg);
        if cfg.servers == self.entries {
            return false;
        }
        info!(
            servers = cfg.servers.len(),
            "config changed; reloading servers"
        );
        self.infos = cfg.server_infos();
        self.entries = cfg.servers;
        true
    }

    /// Pairing fields are fixed for the life of the process.
    fn check_pairing(&self, path: &Path, cfg: &Config) {
        let mut changed = Vec::new();
        if cfg.device_id != self.pairing.device_id {
            changed.push("device id");
        }
        if cfg.relay_url != self.pairing.relay_url {
            changed.push("relay url");
        }
        let key = path.parent().map(keys::load);
        if matches!(key, Some(Ok(k)) if k.verifying_key() != self.pairing.verifying_key) {
            changed.push("device key");
        }
        if !changed.is_empty() {
            warn!(
                changed = changed.join(", "),
                "pairing changed on disk; it is not hot-reloaded, restart `webmcp connect` to use it"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::SessionMode;

    fn config(servers: Vec<ServerEntry>) -> Config {
        Config {
            device_id: "dev_0123456789abcdef".into(),
            handle: "alice".into(),
            device_name: "macbook".into(),
            org_id: None,
            base_url: "https://webmcp.fast".into(),
            relay_url: "wss://webmcp.fast/connect".into(),
            hardware_id: "ab".repeat(32),
            servers,
        }
    }

    fn watcher(dir: &Path, cfg: &Config) -> ConfigWatcher {
        ConfigWatcher::new(
            Some(Config::path_in(dir)),
            Duration::from_millis(10),
            Pairing {
                device_id: cfg.device_id.clone(),
                relay_url: cfg.relay_url.clone(),
                verifying_key: keys::generate().verifying_key(),
            },
            cfg.servers.clone(),
            cfg.server_infos(),
        )
    }

    #[tokio::test]
    async fn poll_applies_changes_and_survives_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let a = ServerEntry::stdio("a", "srv a", SessionMode::PerSession).unwrap();
        let b = ServerEntry::stdio("b", "srv b", SessionMode::Shared).unwrap();
        let mut cfg = config(vec![a.clone()]);
        cfg.save_to(dir.path()).unwrap();
        let mut w = watcher(dir.path(), &cfg);
        // First look: same set as the seed.
        assert!(!w.poll());
        assert!(!w.poll());

        cfg.servers.push(b.clone());
        cfg.save_to(dir.path()).unwrap();
        assert!(w.poll());
        assert_eq!(w.entries(), [a.clone(), b.clone()]);
        assert_eq!(w.infos(), cfg.server_infos());
        assert!(!w.poll());

        std::fs::write(Config::path_in(dir.path()), "servers = [[[").unwrap();
        assert!(!w.poll());
        assert!(!w.poll());
        assert_eq!(w.entries().len(), 2);

        // Pairing fields changing is ignored; the server list still applies.
        cfg.device_id = "dev_ffffffffffffffff".into();
        cfg.servers.remove(0);
        cfg.save_to(dir.path()).unwrap();
        assert!(w.poll());
        assert_eq!(w.entries(), [b]);

        std::fs::remove_file(Config::path_in(dir.path())).unwrap();
        assert!(!w.poll());
        assert_eq!(w.entries().len(), 1);
    }

    #[tokio::test]
    async fn disabled_without_a_path() {
        let cfg = config(vec![]);
        let mut w = ConfigWatcher::new(
            None,
            Duration::from_millis(1),
            Pairing {
                device_id: cfg.device_id.clone(),
                relay_url: cfg.relay_url.clone(),
                verifying_key: keys::generate().verifying_key(),
            },
            vec![],
            vec![],
        );
        assert!(!w.poll());
        let waited = tokio::time::timeout(Duration::from_millis(50), w.changed()).await;
        assert!(waited.is_err());
    }
}
