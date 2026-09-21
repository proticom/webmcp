//! One daemon per device: an exclusive advisory lock in the config directory.
//!
//! Two `webmcp connect` processes for the same device fight forever: the
//! gateway lets the newcomer replace the old socket, the old one reconnects
//! and replaces it back. The lock stops the second one before it dials.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Name of the lock file inside the config directory. It is never removed:
/// unlinking a lock file races with the next process opening it.
pub const LOCK_FILE: &str = "daemon.lock";

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("another `webmcp connect` is already running for this device{}; stop it first (or `webmcp service uninstall` if it is the background service)", pid.map(|p| format!(" (pid {p})")).unwrap_or_default())]
    Held { pid: Option<u32>, path: PathBuf },
    #[error("could not take the instance lock ({path}): {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Held for the life of `webmcp connect`. The kernel drops the lock when the
/// file closes, so a crash never leaves a stale one behind.
#[derive(Debug)]
pub struct InstanceLock {
    file: File,
    path: PathBuf,
}

impl InstanceLock {
    /// Take the lock in `dir`, or report who holds it.
    pub fn acquire(dir: &Path) -> Result<Self, LockError> {
        let path = dir.join(LOCK_FILE);
        let io = |source| LockError::Io {
            path: path.clone(),
            source,
        };
        std::fs::create_dir_all(dir).map_err(io)?;
        // No truncate: a loser must still be able to read the holder's pid.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(io)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                let mut text = String::new();
                let _ = file.read_to_string(&mut text);
                return Err(LockError::Held {
                    pid: text.trim().parse().ok(),
                    path,
                });
            }
            Err(TryLockError::Error(e)) => return Err(io(e)),
        }
        // The pid is a courtesy for the error message above, not the lock.
        file.set_len(0)
            .and_then(|_| file.seek(SeekFrom::Start(0)))
            .and_then(|_| writeln!(file, "{}", std::process::id()))
            .and_then(|_| file.flush())
            .map_err(io)?;
        Ok(InstanceLock { file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquisition_fails_while_held_and_names_the_pid() {
        let dir = tempfile::tempdir().unwrap();
        let first = InstanceLock::acquire(dir.path()).unwrap();
        assert_eq!(first.path(), dir.path().join(LOCK_FILE));
        match InstanceLock::acquire(dir.path()) {
            Err(e @ LockError::Held { pid, .. }) => {
                assert_eq!(pid, Some(std::process::id()));
                assert!(e
                    .to_string()
                    .contains(&format!("pid {}", std::process::id())));
            }
            other => panic!("expected Held, got {other:?}"),
        }
    }

    #[test]
    fn released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        drop(InstanceLock::acquire(dir.path()).unwrap());
        let again = InstanceLock::acquire(dir.path()).unwrap();
        drop(again);
        // The file stays; only the lock goes.
        assert!(dir.path().join(LOCK_FILE).exists());
    }
}
