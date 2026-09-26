//! Run `webmcp connect` as a per-user background service, so the device stays
//! online across logouts, reboots and crashes. macOS (launchd LaunchAgent)
//! and Linux (systemd user unit); Windows is not supported yet.
//!
//! Both run as the user, in the user's session, with the user's files, and
//! need no sudo: a LaunchAgent (not a LaunchDaemon) on macOS, a `--user` unit
//! (not a system one) on Linux.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::Error;

/// launchd label (macOS).
pub const LABEL: &str = "fast.webmcp.daemon";
/// systemd unit name (Linux).
pub const UNIT: &str = "webmcp.service";
/// Set in the service's environment so `connect` knows a supervisor restarts it.
pub const SERVICE_ENV: &str = "WEBMCP_SERVICE";

/// Whether `webmcp service` works on this platform.
pub fn supported() -> bool {
    cfg!(any(target_os = "macos", target_os = "linux"))
}

/// Everything the service definition needs, gathered from the installing shell.
pub struct ServiceSpec {
    /// Absolute path of the `webmcp` binary to run.
    pub program: PathBuf,
    /// The installing shell's PATH. launchd's and systemd's own PATH is
    /// minimal, and stdio servers are usually launched through `npx`, `uvx`,
    /// or a `#!/usr/bin/env node` shim, none of which would be found without it.
    pub path_env: String,
    pub home: PathBuf,
    /// Passed through when the daemon uses a non-default config directory.
    pub config_dir: Option<PathBuf>,
    pub log_file: PathBuf,
}

/// Where the service definition lives: the LaunchAgent plist on macOS, the
/// systemd user unit elsewhere.
pub fn definition_path(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        plist_path(home)
    } else {
        unit_path(home)
    }
}

pub fn plist_path(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

/// `~/.config/systemd/user/webmcp.service`, the per-user unit directory
/// systemd reads without root.
pub fn unit_path(home: &Path) -> PathBuf {
    home.join(".config/systemd/user").join(UNIT)
}

pub fn log_path(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library/Logs/webmcp/daemon.log")
    } else {
        home.join(".local/state/webmcp/daemon.log")
    }
}

/// One line the user may need after `install`, or none.
pub fn post_install_hint() -> Option<&'static str> {
    if cfg!(target_os = "linux") {
        Some("To keep it running when you are not logged in: loginctl enable-linger $USER")
    } else {
        None
    }
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

/// Quote one word for a systemd unit file (`ExecStart=`, `Environment=`):
/// double quotes, backslash escapes inside them, and `%` doubled so systemd
/// does not read it as a specifier.
fn unit_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '%' => out.push_str("%%"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The systemd user unit. `Restart=on-failure` is the launchd
/// `SuccessfulExit=false`: restart after a crash or a non-zero exit, but not
/// after a clean exit, which is how the daemon says "pair this machine again"
/// without spinning. Logs go to a file rather than only the journal so
/// `webmcp service status` can name them.
pub fn unit(spec: &ServiceSpec) -> String {
    let mut env = format!(
        "Environment={}\nEnvironment={}\nEnvironment={}\n",
        unit_quote(&format!("PATH={}", spec.path_env)),
        unit_quote(&format!("HOME={}", spec.home.display())),
        unit_quote(&format!("{SERVICE_ENV}=1")),
    );
    if let Some(dir) = &spec.config_dir {
        env.push_str(&format!(
            "Environment={}\n",
            unit_quote(&format!(
                "{}={}",
                crate::config::CONFIG_DIR_ENV,
                dir.display()
            ))
        ));
    }
    let log = spec.log_file.display().to_string();
    format!(
        "[Unit]
Description=webmcp.fast daemon: relays local MCP servers
Documentation=https://github.com/proticom/webmcp
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={program} connect
{env}Restart=on-failure
RestartSec=10
KillSignal=SIGTERM
TimeoutStopSec=15
StandardOutput=append:{log_out}
StandardError=append:{log_err}

[Install]
WantedBy=default.target
",
        program = unit_quote(&spec.program.display().to_string()),
        log_out = unit_quote(&log),
        log_err = unit_quote(&log),
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

fn systemctl(args: &[&str]) -> Result<std::process::Output, Error> {
    Command::new("systemctl")
        .arg("--user")
        .args(args)
        .output()
        .map_err(|e| Error::io("run systemctl", Path::new("systemctl"), e))
}

fn systemctl_ok(args: &[&str]) -> Result<(), Error> {
    let out = systemctl(args)?;
    if out.status.success() {
        Ok(())
    } else {
        Err(Error::Invalid {
            field: "systemctl",
            reason: format!(
                "systemctl --user {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        })
    }
}

fn require_supported() -> Result<(), Error> {
    if supported() {
        Ok(())
    } else {
        Err(Error::Invalid {
            field: "platform",
            reason: "`webmcp service` supports macOS (launchd) and Linux (systemd --user) only; run `webmcp connect` under your own supervisor".into(),
        })
    }
}

fn create_parents(path: &Path, log_file: &Path) -> Result<(), Error> {
    for dir in [path.parent(), log_file.parent()].into_iter().flatten() {
        std::fs::create_dir_all(dir).map_err(|e| Error::io("create directory", dir, e))?;
    }
    Ok(())
}

/// Write the definition and (re)load it. Safe to run again after upgrading
/// or after the shell's PATH changed. Returns the definition's path.
pub fn install(spec: &ServiceSpec) -> Result<PathBuf, Error> {
    require_supported()?;
    if cfg!(target_os = "macos") {
        install_launchd(spec)
    } else {
        install_systemd(spec)
    }
}

fn install_launchd(spec: &ServiceSpec) -> Result<PathBuf, Error> {
    let path = plist_path(&spec.home);
    create_parents(&path, &spec.log_file)?;
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

fn install_systemd(spec: &ServiceSpec) -> Result<PathBuf, Error> {
    let path = unit_path(&spec.home);
    create_parents(&path, &spec.log_file)?;
    std::fs::write(&path, unit(spec)).map_err(|e| Error::io("write systemd unit", &path, e))?;
    systemctl_ok(&["daemon-reload"])?;
    systemctl_ok(&["enable", UNIT])?;
    // `enable --now` would leave an already-running instance on the old
    // definition; restart picks up the new binary and PATH either way.
    systemctl_ok(&["restart", UNIT])?;
    Ok(path)
}

/// Stop the service and remove its definition. Pairing and attached servers
/// are untouched. `Ok(false)` when nothing was installed.
pub fn uninstall(home: &Path) -> Result<bool, Error> {
    require_supported()?;
    let path = definition_path(home);
    if cfg!(target_os = "macos") {
        let _ = launchctl(&["bootout", &format!("{}/{LABEL}", domain())]);
    } else {
        // Not installed is not an error here; the file check below decides.
        let _ = systemctl(&["disable", "--now", UNIT]);
    }
    let removed = match std::fs::remove_file(&path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(Error::io("remove service definition", &path, e)),
    };
    if cfg!(target_os = "linux") && removed {
        let _ = systemctl(&["daemon-reload"]);
    }
    Ok(removed)
}

pub struct ServiceStatus {
    pub installed: bool,
    /// The running process, if the supervisor reports one.
    pub pid: Option<u32>,
}

pub fn status(home: &Path) -> Result<ServiceStatus, Error> {
    require_supported()?;
    let installed = definition_path(home).exists();
    let pid = if cfg!(target_os = "macos") {
        let out = launchctl(&["print", &format!("{}/{LABEL}", domain())]);
        out.ok().filter(|o| o.status.success()).and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .find_map(|l| l.trim().strip_prefix("pid = ")?.trim().parse().ok())
        })
    } else {
        let out = systemctl(&["show", "-p", "MainPID", "--value", UNIT]);
        out.ok()
            .filter(|o| o.status.success())
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u32>()
                    .ok()
            })
            .filter(|pid| *pid != 0)
    };
    Ok(ServiceStatus { installed, pid })
}

/// The Node version manager whose per-version directory holds `program`, if
/// any. A service pinned there breaks when the user switches Node versions.
pub fn node_version_manager(program: &Path) -> Option<&'static str> {
    let p = program.to_string_lossy().replace('\\', "/");
    [
        ("/.nvm/versions/", "nvm"),
        ("/fnm_multishells/", "fnm"),
        ("/.local/share/fnm/", "fnm"),
        ("/.asdf/installs/", "asdf"),
        ("/.volta/tools/image/", "Volta"),
        ("/n/versions/", "n"),
    ]
    .into_iter()
    .find(|(needle, _)| p.contains(needle))
    .map(|(_, name)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spots_node_version_manager_paths() {
        let nvm = Path::new("/Users/x/.nvm/versions/node/v22.17.1/lib/node_modules/@proticom/webmcp-darwin-arm64/webmcp");
        assert_eq!(node_version_manager(nvm), Some("nvm"));
        assert_eq!(
            node_version_manager(Path::new(
                "/opt/homebrew/lib/node_modules/@proticom/webmcp-darwin-arm64/webmcp"
            )),
            None
        );
        assert_eq!(
            node_version_manager(Path::new("/Users/x/.local/bin/webmcp")),
            None
        );
    }

    fn spec() -> ServiceSpec {
        ServiceSpec {
            program: "/Users/a&b/.cargo/bin/webmcp".into(),
            path_env: "/opt/homebrew/bin:/usr/bin".into(),
            home: "/Users/a&b".into(),
            config_dir: None,
            log_file: "/Users/a&b/Library/Logs/webmcp/daemon.log".into(),
        }
    }

    fn linux_spec() -> ServiceSpec {
        ServiceSpec {
            program: "/home/a b/.local/bin/webmcp".into(),
            path_env: "/home/a b/.nvm/versions/node/v22/bin:/usr/local/bin:/usr/bin:/bin".into(),
            home: "/home/a b".into(),
            config_dir: None,
            log_file: "/home/a b/.local/state/webmcp/daemon.log".into(),
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
            unit_path(home),
            Path::new("/Users/x/.config/systemd/user/webmcp.service")
        );
        let log = log_path(home);
        if cfg!(target_os = "macos") {
            assert_eq!(log, Path::new("/Users/x/Library/Logs/webmcp/daemon.log"));
        } else {
            assert_eq!(log, Path::new("/Users/x/.local/state/webmcp/daemon.log"));
        }
    }

    #[test]
    fn unit_runs_connect_with_the_callers_path_and_quotes_words() {
        let u = unit(&linux_spec());
        assert!(u.contains("ExecStart=\"/home/a b/.local/bin/webmcp\" connect\n"));
        assert!(u.contains(
            "Environment=\"PATH=/home/a b/.nvm/versions/node/v22/bin:/usr/local/bin:/usr/bin:/bin\"\n"
        ));
        assert!(u.contains("Environment=\"HOME=/home/a b\"\n"));
        assert!(u.contains("Environment=\"WEBMCP_SERVICE=1\"\n"));
        assert!(u.contains("Restart=on-failure\n"));
        assert!(u.contains("StandardOutput=append:\"/home/a b/.local/state/webmcp/daemon.log\"\n"));
        assert!(u.contains("WantedBy=default.target\n"));
        assert!(!u.contains(crate::config::CONFIG_DIR_ENV));
        // Sections in order, nothing unquoted with a space in it.
        let unit_i = u.find("[Unit]").unwrap();
        let service_i = u.find("[Service]").unwrap();
        let install_i = u.find("[Install]").unwrap();
        assert!(unit_i < service_i && service_i < install_i);
    }

    #[test]
    fn unit_passes_a_custom_config_dir_through() {
        let mut s = linux_spec();
        s.config_dir = Some("/tmp/cfg".into());
        assert!(unit(&s).contains("Environment=\"WEBMCP_CONFIG_DIR=/tmp/cfg\"\n"));
    }

    #[test]
    fn unit_escapes_specifiers_quotes_and_backslashes() {
        let mut s = linux_spec();
        s.program = "/opt/100%/we\"b\\mcp".into();
        let u = unit(&s);
        assert!(u.contains("ExecStart=\"/opt/100%%/we\\\"b\\\\mcp\" connect\n"));
        assert_eq!(unit_quote("plain"), "\"plain\"");
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

    /// systemd's own checker must accept what we write, where it exists.
    #[cfg(target_os = "linux")]
    #[test]
    fn unit_passes_systemd_analyze_verify() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(UNIT);
        std::fs::write(&file, unit(&linux_spec())).unwrap();
        let Ok(out) = Command::new("systemd-analyze")
            .args(["--user", "verify"])
            .arg(&file)
            .output()
        else {
            eprintln!("systemd-analyze not found; skipping");
            return;
        };
        // Verify complains about the absent binary; that is fine. Any
        // "Failed to parse" or "Unknown key" line is not.
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !err.contains("Failed to parse") && !err.contains("Unknown key"),
            "{err}"
        );
    }
}
