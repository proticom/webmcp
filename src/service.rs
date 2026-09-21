//! Run `webmcp connect` as a per-user background service, so the device stays
//! online across logouts, reboots and crashes. macOS (launchd) for now.
//!
//! The service is a LaunchAgent, not a LaunchDaemon: it runs as the user, in
//! the user's session, with the user's files and keychain, and needs no sudo.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::Error;

pub const LABEL: &str = "fast.webmcp.daemon";
/// Set in the service's environment so `connect` knows a supervisor restarts it.
pub const SERVICE_ENV: &str = "WEBMCP_SERVICE";

/// Everything the plist needs, gathered from the installing shell.
pub struct ServiceSpec {
    /// Absolute path of the `webmcp` binary to run.
    pub program: PathBuf,
    /// The installing shell's PATH. launchd's own PATH is minimal, and stdio
    /// servers are usually launched through `npx`, `uvx`, or a `#!/usr/bin/env
    /// node` shim, none of which would be found without it.
    pub path_env: String,
    pub home: PathBuf,
    /// Passed through when the daemon uses a non-default config directory.
    pub config_dir: Option<PathBuf>,
    pub log_file: PathBuf,
}

pub fn plist_path(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

pub fn log_path(home: &Path) -> PathBuf {
    home.join("Library/Logs/webmcp/daemon.log")
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The LaunchAgent definition. `KeepAlive/SuccessfulExit=false` restarts the
/// daemon after a crash but not after it exits cleanly, which is how it
/// reports "pair this machine again" without spinning.
pub fn plist(spec: &ServiceSpec) -> String {
    let mut env = format!(
        "    <key>PATH</key><string>{}</string>\n    <key>HOME</key><string>{}</string>\n    <key>{SERVICE_ENV}</key><string>1</string>\n",
        xml(&spec.path_env),
        xml(&spec.home.display().to_string()),
    );
    if let Some(dir) = &spec.config_dir {
        env.push_str(&format!(
            "    <key>{}</key><string>{}</string>\n",
            crate::config::CONFIG_DIR_ENV,
            xml(&dir.display().to_string())
        ));
    }
    let log = xml(&spec.log_file.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{program}</string>
    <string>connect</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
{env}  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key><false/>
  </dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ExitTimeOut</key><integer>15</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
        program = xml(&spec.program.display().to_string()),
    )
}

/// launchd's per-user GUI domain, `gui/<uid>`.
fn domain() -> String {
    let uid = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "501".into());
    format!("gui/{uid}")
}

fn launchctl(args: &[&str]) -> std::io::Result<std::process::Output> {
    Command::new("/bin/launchctl").args(args).output()
}

fn require_macos() -> Result<(), Error> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        Err(Error::Invalid {
            field: "platform",
            reason: "`webmcp service` supports macOS only for now; run `webmcp connect` under your own supervisor".into(),
        })
    }
}

/// Write the plist and (re)load it. Safe to run again after upgrading or
/// after the shell's PATH changed.
pub fn install(spec: &ServiceSpec) -> Result<PathBuf, Error> {
    require_macos()?;
    let path = plist_path(&spec.home);
    for dir in [path.parent(), spec.log_file.parent()]
        .into_iter()
        .flatten()
    {
        std::fs::create_dir_all(dir).map_err(|e| Error::io("create directory", dir, e))?;
    }
    std::fs::write(&path, plist(spec)).map_err(|e| Error::io("write launch agent", &path, e))?;
    let target = format!("{}/{LABEL}", domain());
    // Replace a previous definition; "not loaded" is the normal first-run answer.
    let _ = launchctl(&["bootout", &target]);
    let out = launchctl(&["bootstrap", &domain(), &path.display().to_string()])
        .map_err(|e| Error::io("run launchctl", Path::new("/bin/launchctl"), e))?;
    if !out.status.success() {
        return Err(Error::Invalid {
            field: "launchctl bootstrap",
            reason: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(path)
}

/// Stop the service and remove its definition. Pairing and attached servers
/// are untouched.
pub fn uninstall(home: &Path) -> Result<bool, Error> {
    require_macos()?;
    let path = plist_path(home);
    let _ = launchctl(&["bootout", &format!("{}/{LABEL}", domain())]);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::io("remove launch agent", &path, e)),
    }
}

pub struct ServiceStatus {
    pub installed: bool,
    /// The running process, if launchd reports one.
    pub pid: Option<u32>,
}

pub fn status(home: &Path) -> Result<ServiceStatus, Error> {
    require_macos()?;
    let installed = plist_path(home).exists();
    let out = launchctl(&["print", &format!("{}/{LABEL}", domain())]);
    let pid = out.ok().filter(|o| o.status.success()).and_then(|o| {
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .find_map(|l| l.trim().strip_prefix("pid = ")?.trim().parse().ok())
    });
    Ok(ServiceStatus { installed, pid })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ServiceSpec {
        ServiceSpec {
            program: "/Users/a&b/.cargo/bin/webmcp".into(),
            path_env: "/opt/homebrew/bin:/usr/bin".into(),
            home: "/Users/a&b".into(),
            config_dir: None,
            log_file: "/Users/a&b/Library/Logs/webmcp/daemon.log".into(),
        }
    }

    #[test]
    fn plist_runs_connect_with_the_callers_path_and_escapes_xml() {
        let p = plist(&spec());
        assert!(p.contains(
            "<string>/Users/a&amp;b/.cargo/bin/webmcp</string>\n    <string>connect</string>"
        ));
        assert!(p.contains("<key>PATH</key><string>/opt/homebrew/bin:/usr/bin</string>"));
        assert!(p.contains("<key>WEBMCP_SERVICE</key><string>1</string>"));
        assert!(p.contains("<key>SuccessfulExit</key><false/>"));
        assert!(!p.contains("a&b"));
        assert!(!p.contains(crate::config::CONFIG_DIR_ENV));
    }

    #[test]
    fn plist_passes_a_custom_config_dir_through() {
        let mut s = spec();
        s.config_dir = Some("/tmp/cfg".into());
        assert!(plist(&s).contains("<key>WEBMCP_CONFIG_DIR</key><string>/tmp/cfg</string>"));
    }

    #[test]
    fn paths_live_under_the_users_library() {
        let home = Path::new("/Users/x");
        assert_eq!(
            plist_path(home),
            Path::new("/Users/x/Library/LaunchAgents/fast.webmcp.daemon.plist")
        );
        assert_eq!(
            log_path(home),
            Path::new("/Users/x/Library/Logs/webmcp/daemon.log")
        );
    }

    /// Apple's own parser must accept what we write.
    #[cfg(target_os = "macos")]
    #[test]
    fn plist_passes_plutil_lint() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("agent.plist");
        std::fs::write(&file, plist(&spec())).unwrap();
        let out = Command::new("/usr/bin/plutil")
            .arg("-lint")
            .arg(&file)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}
