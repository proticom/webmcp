//! On-disk configuration (`config.toml`) and its location.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::proto::{ServerInfo, ServerStatus, SessionMode, Transport};

/// Name of the config file inside the config directory.
pub const CONFIG_FILE: &str = "config.toml";

/// Environment variable that overrides the config directory (tests, CI).
pub const CONFIG_DIR_ENV: &str = "WEBMCP_CONFIG_DIR";

/// Regex-equivalent of `^[a-z0-9][a-z0-9-]{0,31}$`, shared by aliases and
/// device names.
pub fn is_valid_alias(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    let ok = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-';
    bytes[0] != b'-' && bytes.iter().all(ok)
}

/// Device names follow the gateway's rule: an alias that also ends in a
/// letter or digit.
pub fn is_valid_device_name(s: &str) -> bool {
    is_valid_alias(s) && !s.ends_with('-')
}

/// Resolve the config directory.
///
/// `$WEBMCP_CONFIG_DIR` wins. Otherwise: `~/Library/Application Support/webmcp/`
/// on macOS, `$XDG_CONFIG_HOME/webmcp/` or `~/.config/webmcp/` elsewhere
/// (`%APPDATA%\webmcp\config` on Windows).
pub fn config_dir() -> Result<PathBuf, Error> {
    if let Some(dir) = std::env::var_os(CONFIG_DIR_ENV).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    directories::ProjectDirs::from("", "", "webmcp")
        .map(|d| d.config_dir().to_path_buf())
        .ok_or(Error::NoConfigDir)
}

/// Persistent daemon state. Everything here is safe to print; the private
/// key lives in `device.key` (see [`crate::keys`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub device_id: String,
    pub handle: String,
    pub device_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    pub base_url: String,
    pub relay_url: String,
    pub hardware_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<ServerEntry>,
}

/// One attached MCP server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerEntry {
    pub alias: String,
    pub transport: Transport,
    /// Shell command line for `stdio` servers (parsed with shell quoting).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Endpoint URL for `http` servers (must be loopback).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default)]
    pub mode: SessionMode,
    /// Extra environment for the spawned `stdio` process (added to the
    /// daemon's own environment).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Working directory of the spawned `stdio` process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    /// Concurrent sessions allowed on this server; `None` means the
    /// daemon default ([`crate::relay::DEFAULT_MAX_SESSIONS`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sessions: Option<usize>,
}

/// Advertised for `shared` stdio servers until id remapping lands.
pub const SHARED_STDIO_UNSUPPORTED: &str =
    "shared mode over stdio is not supported yet; use per-session";

impl ServerEntry {
    /// Build and validate a stdio entry.
    pub fn stdio(alias: &str, command: &str, mode: SessionMode) -> Result<Self, Error> {
        validate_alias(alias)?;
        let words = shell_words::split(command).map_err(|e| Error::Invalid {
            field: "command",
            reason: e.to_string(),
        })?;
        if words.is_empty() {
            return Err(Error::Invalid {
                field: "command",
                reason: "command is empty".into(),
            });
        }
        Ok(ServerEntry {
            alias: alias.to_string(),
            transport: Transport::Stdio,
            command: Some(command.trim().to_string()),
            url: None,
            mode,
            env: BTreeMap::new(),
            cwd: None,
            max_sessions: None,
        })
    }

    /// Build and validate an http entry. The URL must be `http(s)://` and
    /// point at `localhost`, `127.0.0.1` or `::1`.
    pub fn http(alias: &str, url: &str, mode: SessionMode) -> Result<Self, Error> {
        validate_alias(alias)?;
        validate_local_http_url(url)?;
        Ok(ServerEntry {
            alias: alias.to_string(),
            transport: Transport::Http,
            command: None,
            url: Some(url.to_string()),
            mode,
            env: BTreeMap::new(),
            cwd: None,
            max_sessions: None,
        })
    }

    /// Human-readable target (command or URL).
    pub fn target(&self) -> &str {
        self.command
            .as_deref()
            .or(self.url.as_deref())
            .unwrap_or("")
    }

    /// The stdio command line split into program and arguments.
    pub fn argv(&self) -> Result<Vec<String>, Error> {
        let command = self.command.as_deref().unwrap_or("");
        let words = shell_words::split(command).map_err(|e| Error::Invalid {
            field: "command",
            reason: e.to_string(),
        })?;
        if words.is_empty() {
            return Err(Error::Invalid {
                field: "command",
                reason: "command is empty".into(),
            });
        }
        Ok(words)
    }

    /// True for the one combination the relay cannot serve yet: a single
    /// stdio process multiplexed across sessions.
    pub fn is_unsupported(&self) -> bool {
        self.transport == Transport::Stdio && self.mode == SessionMode::Shared
    }

    /// The `servers`-frame entry for this server. Processes are spawned per
    /// session, so a server is `ready` unless its mode cannot be served.
    pub fn info(&self) -> ServerInfo {
        let unsupported = self.is_unsupported();
        ServerInfo {
            alias: self.alias.clone(),
            transport: self.transport,
            mode: self.mode,
            status: if unsupported {
                ServerStatus::Error
            } else {
                ServerStatus::Ready
            },
            error: unsupported.then(|| SHARED_STDIO_UNSUPPORTED.to_string()),
        }
    }
}

pub fn validate_alias(alias: &str) -> Result<(), Error> {
    if is_valid_alias(alias) {
        Ok(())
    } else {
        Err(Error::Invalid {
            field: "alias",
            reason: format!("`{alias}` must match ^[a-z0-9][a-z0-9-]{{0,31}}$"),
        })
    }
}

pub fn validate_local_http_url(raw: &str) -> Result<(), Error> {
    let invalid = |reason: String| Error::Invalid {
        field: "url",
        reason,
    };
    let url = url::Url::parse(raw).map_err(|e| invalid(e.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid(format!(
            "scheme must be http or https, got `{}`",
            url.scheme()
        )));
    }
    match url.host() {
        Some(url::Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") => Ok(()),
        Some(url::Host::Ipv4(ip)) if ip.is_loopback() => Ok(()),
        Some(url::Host::Ipv6(ip)) if ip.is_loopback() => Ok(()),
        Some(h) => Err(invalid(format!(
            "host must be localhost, 127.0.0.1 or ::1, got `{h}`"
        ))),
        None => Err(invalid("missing host".into())),
    }
}

impl Config {
    /// Path of `config.toml` inside `dir`.
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(CONFIG_FILE)
    }

    /// Load from `dir/config.toml`. A missing file is [`Error::NotPaired`].
    pub fn load_from(dir: &Path) -> Result<Config, Error> {
        Self::load_path(&Self::path_in(dir))
    }

    /// Load from the config file at `path` (what the hot-reload poll uses).
    pub fn load_path(path: &Path) -> Result<Config, Error> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::NotPaired
            } else {
                Error::io("read config", path, e)
            }
        })?;
        toml::from_str(&text).map_err(|e| Error::Corrupt(format!("{}: {e}", path.display())))
    }

    /// Load from `dir/config.toml`, returning `None` if it does not exist.
    pub fn try_load_from(dir: &Path) -> Result<Option<Config>, Error> {
        match Self::load_from(dir) {
            Ok(c) => Ok(Some(c)),
            Err(Error::NotPaired) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Write to `dir/config.toml` atomically, readable by the owner only:
    /// `env` values copied from other tools' configs can be API keys.
    pub fn save_to(&self, dir: &Path) -> Result<(), Error> {
        std::fs::create_dir_all(dir).map_err(|e| Error::io("create config dir", dir, e))?;
        let path = Self::path_in(dir);
        let tmp = dir.join(format!("{CONFIG_FILE}.tmp"));
        let text = toml::to_string_pretty(self).map_err(|e| Error::Corrupt(e.to_string()))?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        {
            use std::io::Write;
            let mut f = opts
                .open(&tmp)
                .map_err(|e| Error::io("create config", &tmp, e))?;
            f.write_all(text.as_bytes())
                .map_err(|e| Error::io("write config", &tmp, e))?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| Error::io("chmod config", &tmp, e))?;
        }
        std::fs::rename(&tmp, &path).map_err(|e| Error::io("rename config", &path, e))?;
        Ok(())
    }

    /// Add a server; the alias must be unused.
    pub fn attach(&mut self, entry: ServerEntry) -> Result<(), Error> {
        if self.servers.iter().any(|s| s.alias == entry.alias) {
            return Err(Error::AliasExists(entry.alias));
        }
        self.servers.push(entry);
        Ok(())
    }

    /// Remove a server by alias.
    pub fn detach(&mut self, alias: &str) -> Result<ServerEntry, Error> {
        let idx = self
            .servers
            .iter()
            .position(|s| s.alias == alias)
            .ok_or_else(|| Error::NoSuchAlias(alias.to_string()))?;
        Ok(self.servers.remove(idx))
    }

    /// The `servers` frame payload for the current attached set.
    pub fn server_infos(&self) -> Vec<ServerInfo> {
        self.servers.iter().map(ServerEntry::info).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        Config {
            device_id: "dev_0123456789abcdef".into(),
            handle: "alice".into(),
            device_name: "macbook".into(),
            org_id: Some("org_1".into()),
            base_url: "https://webmcp.fast".into(),
            relay_url: "wss://webmcp.fast/connect".into(),
            hardware_id: "ab".repeat(32),
            servers: vec![],
        }
    }

    #[test]
    fn alias_pattern() {
        for ok in ["a", "gnosys", "a-b-1", &"a".repeat(32)] {
            assert!(is_valid_alias(ok), "{ok}");
        }
        for bad in ["", "-a", "A", "a_b", "a b", &"a".repeat(33), "é"] {
            assert!(!is_valid_alias(bad), "{bad}");
        }
    }

    #[test]
    fn device_name_must_end_in_letter_or_digit() {
        for ok in ["a", "mac-studio", "box-01"] {
            assert!(is_valid_device_name(ok), "{ok}");
        }
        for bad in ["mac-", "-mac", "", "Mac"] {
            assert!(!is_valid_device_name(bad), "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn config_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(Config::path_in(dir.path()), "stale").unwrap();
        std::fs::set_permissions(
            Config::path_in(dir.path()),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        sample().save_to(dir.path()).unwrap();
        let mode = std::fs::metadata(Config::path_in(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn local_urls_only() {
        for ok in [
            "http://localhost:3000/mcp",
            "https://LOCALHOST/mcp",
            "http://127.0.0.1:8080",
            "http://127.1.2.3/",
            "http://[::1]:9000/mcp",
        ] {
            validate_local_http_url(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "http://example.com/mcp",
            "ws://localhost/",
            "localhost:3000",
            "http://10.0.0.1/",
            "http://[::2]/",
            "file:///etc/passwd",
        ] {
            assert!(validate_local_http_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn stdio_requires_command() {
        assert!(ServerEntry::stdio("x", "   ", SessionMode::Shared).is_err());
        assert!(ServerEntry::stdio("x", "npx -y 'unterminated", SessionMode::Shared).is_err());
        let e = ServerEntry::stdio("x", "npx -y foo", SessionMode::Shared).unwrap();
        assert_eq!(e.target(), "npx -y foo");
    }

    #[test]
    fn roundtrip_with_servers() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = sample();
        cfg.attach(
            ServerEntry::stdio(
                "gnosys",
                "npx -y gnosys --flag \"a b\"",
                SessionMode::PerSession,
            )
            .unwrap(),
        )
        .unwrap();
        cfg.attach(
            ServerEntry::http("web", "http://localhost:3000/mcp", SessionMode::Shared).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            cfg.attach(ServerEntry::http("web", "http://localhost/", SessionMode::Shared).unwrap()),
            Err(Error::AliasExists(_))
        ));
        cfg.save_to(dir.path()).unwrap();
        let back = Config::load_from(dir.path()).unwrap();
        assert_eq!(back, cfg);
        let infos = back.server_infos();
        assert_eq!(infos.len(), 2);
        assert!(infos.iter().all(|i| i.status == ServerStatus::Ready));
        let mut back = back;
        back.detach("web").unwrap();
        assert!(matches!(back.detach("web"), Err(Error::NoSuchAlias(_))));
        assert_eq!(back.servers.len(), 1);
    }

    #[test]
    fn old_config_without_new_fields_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let mut text = toml::to_string_pretty(&sample()).unwrap();
        text.push_str(
            "\n[[servers]]\nalias = \"fs\"\ntransport = \"stdio\"\ncommand = \"npx -y fs /tmp\"\n",
        );
        std::fs::write(Config::path_in(dir.path()), text).unwrap();
        let cfg = Config::load_from(dir.path()).unwrap();
        let fs = &cfg.servers[0];
        assert_eq!(fs.mode, SessionMode::PerSession);
        assert!(fs.env.is_empty() && fs.cwd.is_none() && fs.max_sessions.is_none());
        assert_eq!(fs.argv().unwrap(), ["npx", "-y", "fs", "/tmp"]);
    }

    #[test]
    fn env_and_cwd_roundtrip_and_shared_stdio_is_advertised_as_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = sample();
        let mut e = ServerEntry::stdio("fs", "srv 'a b'", SessionMode::Shared).unwrap();
        e.env.insert("KEY".into(), "v=1".into());
        e.cwd = Some(PathBuf::from("/tmp"));
        e.max_sessions = Some(2);
        cfg.attach(e).unwrap();
        cfg.save_to(dir.path()).unwrap();
        let back = Config::load_from(dir.path()).unwrap();
        assert_eq!(back, cfg);
        assert_eq!(back.servers[0].argv().unwrap(), ["srv", "a b"]);
        let info = back.servers[0].info();
        assert_eq!(info.status, ServerStatus::Error);
        assert_eq!(info.error.as_deref(), Some(SHARED_STDIO_UNSUPPORTED));
    }

    #[test]
    fn missing_config_is_not_paired() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            Config::load_from(dir.path()),
            Err(Error::NotPaired)
        ));
        assert!(Config::try_load_from(dir.path()).unwrap().is_none());
    }
}
