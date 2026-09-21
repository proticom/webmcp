//! Library error type.

use std::path::Path;

/// Errors surfaced by the daemon library. The CLI wraps these in `anyhow`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{what} ({path}): {source}")]
    Io {
        what: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("this machine is not paired yet; run `webmcp up`")]
    NotPaired,
    #[error("corrupt config: {0}")]
    Corrupt(String),
    #[error("invalid {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
    #[error("server alias `{0}` is already attached (detach it first)")]
    AliasExists(String),
    #[error("no server attached with alias `{0}`")]
    NoSuchAlias(String),
    #[error("no config directory could be determined for this platform")]
    NoConfigDir,
}

impl Error {
    pub(crate) fn io(what: &'static str, path: &Path, source: std::io::Error) -> Self {
        Error::Io {
            what,
            path: path.display().to_string(),
            source,
        }
    }
}
