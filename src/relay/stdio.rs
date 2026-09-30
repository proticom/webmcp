//! stdio backend: one child process per session, newline-delimited JSON on
//! its stdin/stdout (MCP stdio framing), stderr to the log.

use std::ffi::OsString;
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tracing::{debug, warn};

use super::{reason, short, SessionCtx, MAX_BACKEND_MESSAGE_BYTES};
use crate::config::ServerEntry;

/// After the child exits, how long its remaining stdout is still drained.
const EXIT_DRAIN: Duration = Duration::from_millis(500);
/// stderr lines longer than this end stderr logging for the session.
const MAX_STDERR_LINE: usize = 64 * 1024;

/// Variables a child inherits from the daemon. Everything else (cloud keys,
/// tokens in the user's shell) stays out unless the entry names it in `env`,
/// because an agent can often make a server echo its environment.
const INHERITED_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "TZ",
    "TERM",
    "TMPDIR",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
    // Windows: what processes need to start and find their profile.
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "USERNAME",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "HOMEDRIVE",
    "HOMEPATH",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
];

fn inherited(name: &str) -> bool {
    let matches = |n: &&str| {
        if cfg!(windows) {
            n.eq_ignore_ascii_case(name)
        } else {
            *n == name
        }
    };
    INHERITED_ENV.iter().any(matches) || name.starts_with("LC_")
}

/// The child's whole environment: the allowlisted part of `parent`, then the
/// entry's own `env` on top.
fn child_env(
    parent: impl IntoIterator<Item = (OsString, OsString)>,
    entry: &ServerEntry,
) -> Vec<(OsString, OsString)> {
    let mut out: Vec<(OsString, OsString)> = parent
        .into_iter()
        .filter(|(k, _)| k.to_str().is_some_and(inherited))
        .collect();
    out.extend(entry.env.iter().map(|(k, v)| (k.into(), v.into())));
    out
}

#[derive(Debug, thiserror::Error)]
enum SpawnError {
    #[error("{0}")]
    Command(#[from] crate::Error),
    #[error("{program}: {source}")]
    Io {
        program: String,
        #[source]
        source: std::io::Error,
    },
}

fn spawn(entry: &ServerEntry) -> Result<Child, SpawnError> {
    let argv = entry.argv()?;
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .env_clear()
        .envs(child_env(std::env::vars_os(), entry))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(cwd) = &entry.cwd {
        cmd.current_dir(cwd);
    }
    cmd.spawn().map_err(|source| SpawnError::Io {
        program: argv[0].clone(),
        source,
    })
}

/// Run one session. Returns the `session_close` reason to report, or `None`
/// when the gateway side closed it (`cancelled` fires).
pub(super) async fn run(
    ctx: &SessionCtx,
    entry: &ServerEntry,
    mut rx: mpsc::Receiver<Value>,
    mut cancelled: oneshot::Receiver<()>,
) -> Option<String> {
    let mut child = match spawn(entry) {
        Ok(child) => child,
        Err(e) => {
            warn!(sid = %ctx.sid, server = %ctx.alias, error = %e, "could not start server");
            return Some(format!(
                "{}: {}",
                reason::SPAWN_FAILED,
                short(&e.to_string())
            ));
        }
    };
    debug!(sid = %ctx.sid, server = %ctx.alias, pid = child.id().unwrap_or(0), "server started");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let mut stdout = BufReader::new(child.stdout.take().expect("stdout is piped"));
    let stderr = BufReader::new(child.stderr.take().expect("stderr is piped"));
    tokio::spawn(log_stderr(stderr, ctx.alias.clone(), ctx.sid.clone()));

    // One gateway message being written to stdin, and how much of it went
    // out. Writing is a select arm of its own so a child that stops reading
    // cannot keep us from draining its stdout.
    let mut pending: Option<(Vec<u8>, usize)> = None;
    let mut line = Vec::new();
    let mut exited = false;
    let mut deadline = Instant::now() + ctx.idle_timeout;

    let why = loop {
        tokio::select! {
            _ = &mut cancelled => break None,
            inbound = rx.recv(), if pending.is_none() => match inbound {
                None => break None,
                Some(msg) => match serde_json::to_vec(&msg) {
                    Ok(mut bytes) => {
                        bytes.push(b'\n');
                        pending = Some((bytes, 0));
                        deadline = Instant::now() + ctx.idle_timeout;
                    }
                    Err(e) => warn!(sid = %ctx.sid, error = %e, "dropping unserializable message"),
                },
            },
            written = async {
                let (bytes, offset) = pending.as_ref().expect("guarded by precondition");
                stdin.write(&bytes[*offset..]).await
            }, if pending.is_some() => match written {
                Ok(n) if n > 0 => {
                    let (bytes, offset) = pending.as_mut().expect("guarded by precondition");
                    *offset += n;
                    if *offset >= bytes.len() {
                        pending = None;
                    }
                }
                Ok(_) => break Some(reason::SERVER_EXITED.to_string()),
                Err(e) => {
                    debug!(sid = %ctx.sid, error = %e, "stdin closed");
                    break Some(reason::SERVER_EXITED.to_string());
                }
            },
            read = read_line_bounded(&mut stdout, &mut line, MAX_BACKEND_MESSAGE_BYTES) => match read {
                Ok(LineRead::Line) => {
                    deadline = Instant::now() + ctx.idle_timeout;
                    let forwarded = forward(ctx, &line).await;
                    line.clear();
                    if !forwarded {
                        break None;
                    }
                }
                Ok(LineRead::TooLong) => {
                    warn!(sid = %ctx.sid, server = %ctx.alias, limit = MAX_BACKEND_MESSAGE_BYTES, "server message too large");
                    break Some(reason::MESSAGE_TOO_LARGE.to_string());
                }
                Ok(LineRead::Eof) => break Some(reason::SERVER_EXITED.to_string()),
                Err(e) => {
                    debug!(sid = %ctx.sid, error = %e, "stdout read failed");
                    break Some(reason::SERVER_EXITED.to_string());
                }
            },
            status = child.wait(), if !exited => {
                exited = true;
                match status {
                    Ok(status) => debug!(sid = %ctx.sid, server = %ctx.alias, %status, "server exited"),
                    Err(e) => debug!(sid = %ctx.sid, error = %e, "wait failed"),
                }
                // Whatever is still buffered in the pipe gets a moment.
                deadline = Instant::now() + EXIT_DRAIN;
            },
            _ = tokio::time::sleep_until(deadline) => {
                break Some(if exited { reason::SERVER_EXITED } else { reason::IDLE }.to_string());
            }
        }
    };

    // `kill_on_drop` covers every other path; this one also reaps.
    if let Err(e) = child.kill().await {
        debug!(sid = %ctx.sid, error = %e, "kill failed");
    }
    why
}

/// Turn one stdout line into an `mcp` frame. `false`: the connection is gone.
async fn forward(ctx: &SessionCtx, line: &[u8]) -> bool {
    if line.iter().all(u8::is_ascii_whitespace) {
        return true;
    }
    match serde_json::from_slice::<Value>(line) {
        Ok(Value::Array(batch)) => {
            // One message at a time, so a batched tools/list answer is
            // filtered like any other.
            for msg in batch.into_iter().filter(Value::is_object) {
                if !ctx.emit(msg).await {
                    return false;
                }
            }
            true
        }
        Ok(msg) if msg.is_object() => ctx.emit(msg).await,
        _ => {
            debug!(
                sid = %ctx.sid,
                server = %ctx.alias,
                line = %String::from_utf8_lossy(&line[..line.len().min(200)]),
                "ignoring non-JSON-RPC stdout line"
            );
            true
        }
    }
}

async fn log_stderr<R: AsyncBufRead + Unpin>(mut stderr: R, alias: String, sid: String) {
    let mut line = Vec::new();
    while let Ok(LineRead::Line) = read_line_bounded(&mut stderr, &mut line, MAX_STDERR_LINE).await
    {
        debug!(server = %alias, %sid, "stderr: {}", String::from_utf8_lossy(&line).trim_end());
        line.clear();
    }
}

#[derive(Debug, PartialEq)]
pub(super) enum LineRead {
    /// `buf` holds one line, without its `\n`.
    Line,
    /// End of stream; a trailing partial line is not a message.
    Eof,
    /// The line passed `max` bytes. `buf` is unspecified.
    TooLong,
}

/// `read_until(b'\n')` with a size cap. Cancel safe: progress lives in `buf`.
pub(super) async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<LineRead> {
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(LineRead::Eof);
        }
        let (take, complete) = match available.iter().position(|b| *b == b'\n') {
            Some(i) => (i, true),
            None => (available.len(), false),
        };
        buf.extend_from_slice(&available[..take]);
        reader.consume(take + usize::from(complete));
        if buf.len() > max {
            return Ok(LineRead::TooLong);
        }
        if complete {
            return Ok(LineRead::Line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_env_keeps_the_allowlist_and_the_entry_env_only() {
        let mut entry = ServerEntry::stdio(
            "s",
            "npx -y @scope/server",
            crate::proto::SessionMode::default(),
        )
        .unwrap();
        entry
            .env
            .insert("GITHUB_TOKEN".into(), "from-config".into());
        entry.env.insert("PATH".into(), "/custom".into());
        let parent = [
            ("PATH", "/usr/bin"),
            ("HOME", "/Users/a"),
            ("LC_ALL", "C"),
            ("AWS_SECRET_ACCESS_KEY", "leak"),
            ("GITHUB_TOKEN", "from-shell"),
            ("OPENAI_API_KEY", "leak"),
        ]
        .map(|(k, v)| (OsString::from(k), OsString::from(v)));
        let got = child_env(parent, &entry);
        let pairs: Vec<(&str, &str)> = got
            .iter()
            .map(|(k, v)| (k.to_str().unwrap(), v.to_str().unwrap()))
            .collect();
        // Later entries win when Command applies them, so the config's PATH overrides.
        assert_eq!(
            pairs,
            [
                ("PATH", "/usr/bin"),
                ("HOME", "/Users/a"),
                ("LC_ALL", "C"),
                ("GITHUB_TOKEN", "from-config"),
                ("PATH", "/custom"),
            ]
        );
    }

    #[tokio::test]
    async fn bounded_lines() {
        let data = b"{\"a\":1}\n\nabcdefghij\ntail";
        let mut r = BufReader::with_capacity(4, &data[..]);
        let mut buf = Vec::new();
        assert_eq!(
            read_line_bounded(&mut r, &mut buf, 8).await.unwrap(),
            LineRead::Line
        );
        assert_eq!(buf, b"{\"a\":1}");
        buf.clear();
        assert_eq!(
            read_line_bounded(&mut r, &mut buf, 8).await.unwrap(),
            LineRead::Line
        );
        assert!(buf.is_empty());
        assert_eq!(
            read_line_bounded(&mut r, &mut buf, 8).await.unwrap(),
            LineRead::TooLong
        );
    }

    #[tokio::test]
    async fn partial_last_line_is_eof() {
        let mut r = BufReader::new(&b"no newline"[..]);
        let mut buf = Vec::new();
        assert_eq!(
            read_line_bounded(&mut r, &mut buf, 64).await.unwrap(),
            LineRead::Eof
        );
    }
}
