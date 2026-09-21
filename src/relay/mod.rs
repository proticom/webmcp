//! The MCP relay (protocol §2, M2 frames): maps each gateway session
//! (`sid`) onto one backend, a spawned stdio process or a local Streamable
//! HTTP endpoint, and moves JSON-RPC messages between the two verbatim.
//!
//! One [`Relay`] lives exactly as long as one WebSocket connection. When the
//! connection drops every session ends with it; a reconnect starts clean.

mod http;
mod sse;
mod stdio;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::config::ServerEntry;
use crate::platform;
use crate::proto::{ClientInfo, Frame, SessionMode, Transport};

/// Largest `mcp` frame accepted from the gateway (wire bytes).
pub const MAX_GATEWAY_FRAME_BYTES: usize = 1 << 20;
/// Largest single message accepted from a backend (one stdio line, one
/// HTTP body or one SSE event).
pub const MAX_BACKEND_MESSAGE_BYTES: usize = 8 << 20;
/// Concurrent sessions per server unless the server entry says otherwise.
pub const DEFAULT_MAX_SESSIONS: usize = 4;
/// A session with no traffic in either direction for this long is closed.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Messages queued per session while its backend starts or is busy.
pub const SESSION_QUEUE: usize = 256;

/// `session_close.reason` values the daemon sends.
pub mod reason {
    pub const UNKNOWN_SERVER: &str = "unknown_server";
    pub const UNKNOWN_SESSION: &str = "unknown_session";
    pub const DUPLICATE_SESSION: &str = "duplicate_session";
    pub const BUSY: &str = "busy";
    pub const TOO_MANY_SESSIONS: &str = "too_many_sessions";
    pub const UNSUPPORTED_MODE: &str = "unsupported_mode";
    pub const SERVER_EXITED: &str = "server_exited";
    pub const IDLE: &str = "idle";
    pub const MESSAGE_TOO_LARGE: &str = "message_too_large";
    pub const OVERLOADED: &str = "overloaded";
    /// Hot reload: the session's alias left the config.
    pub const DETACHED: &str = "detached";
    /// Hot reload: the alias is still attached but its definition changed.
    pub const RECONFIGURED: &str = "reconfigured";
    /// Prefix; followed by `: <short message>`.
    pub const SPAWN_FAILED: &str = "spawn_failed";
}

/// Tunables shared by every session of one connection.
#[derive(Debug, Clone)]
pub struct RelayOptions {
    pub idle_timeout: Duration,
    /// Per-server cap when the entry has no `max_sessions` of its own.
    pub max_sessions: usize,
}

impl Default for RelayOptions {
    fn default() -> Self {
        RelayOptions {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_sessions: DEFAULT_MAX_SESSIONS,
        }
    }
}

/// What a backend task needs to talk back to the gateway.
#[derive(Clone)]
pub(crate) struct SessionCtx {
    pub sid: String,
    pub alias: String,
    pub idle_timeout: Duration,
    out: mpsc::Sender<Message>,
}

impl SessionCtx {
    /// Send one backend message to the gateway as an `mcp` frame. `false`
    /// means the connection is gone and the session should stop.
    pub async fn emit(&self, msg: Value) -> bool {
        let frame = Frame::Mcp {
            sid: self.sid.clone(),
            msg,
        };
        send_frame(&self.out, &frame).await
    }
}

struct SessionHandle {
    /// Distinguishes two sessions that reuse one `sid`.
    id: u64,
    alias: String,
    /// Gateway → backend messages.
    tx: mpsc::Sender<Value>,
    /// Dropping it is the close signal, seen even while `tx` is backed up.
    cancel: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

type Sessions = Arc<Mutex<HashMap<String, SessionHandle>>>;

/// Session table for one connection.
pub struct Relay {
    backends: HashMap<String, ServerEntry>,
    opts: RelayOptions,
    out: mpsc::Sender<Message>,
    http: reqwest::Client,
    sessions: Sessions,
    next_id: u64,
}

impl Relay {
    /// `out` feeds the connection's writer task.
    pub fn new(backends: &[ServerEntry], opts: RelayOptions, out: mpsc::Sender<Message>) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(platform::user_agent())
            .connect_timeout(Duration::from_secs(10))
            // Backends are loopback only; never route them through a proxy.
            .no_proxy()
            .build()
            .expect("static http client config");
        Relay {
            backends: backends
                .iter()
                .map(|e| (e.alias.clone(), e.clone()))
                .collect(),
            opts,
            out,
            http,
            sessions: Arc::default(),
            next_id: 0,
        }
    }

    /// Number of live sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.lock().expect("sessions lock").len()
    }

    /// `session_open`: start a backend for `sid`, or refuse with a
    /// `session_close`. There is no ack; `mcp` frames that follow are queued
    /// until the backend is ready.
    pub async fn open(&mut self, sid: String, server: String, client: Option<ClientInfo>) {
        if let Some(old) = self.take(&sid) {
            warn!(%sid, "session_open for a live sid; closing both");
            stop(old).await;
            self.refuse(&sid, reason::DUPLICATE_SESSION).await;
            return;
        }
        let Some(entry) = self.backends.get(&server).cloned() else {
            debug!(%sid, %server, "session_open for an unknown alias");
            self.refuse(&sid, reason::UNKNOWN_SERVER).await;
            return;
        };
        if entry.is_unsupported() {
            self.refuse(&sid, reason::UNSUPPORTED_MODE).await;
            return;
        }
        let live = {
            let sessions = self.sessions.lock().expect("sessions lock");
            sessions.values().filter(|s| s.alias == server).count()
        };
        // HTTP backends are shared by nature; `exclusive` only guards a
        // spawned process.
        let exclusive = entry.transport == Transport::Stdio && entry.mode == SessionMode::Exclusive;
        if exclusive && live > 0 {
            self.refuse(&sid, reason::BUSY).await;
            return;
        }
        if live >= entry.max_sessions.unwrap_or(self.opts.max_sessions) {
            self.refuse(&sid, reason::TOO_MANY_SESSIONS).await;
            return;
        }

        let client_name = client
            .as_ref()
            .and_then(|c| c.name.as_deref())
            .unwrap_or("");
        info!(%sid, %server, client = client_name, transport = %entry.transport, "session opened");

        self.next_id += 1;
        let id = self.next_id;
        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
        let (cancel, cancelled) = oneshot::channel();
        let ctx = SessionCtx {
            sid: sid.clone(),
            alias: server.clone(),
            idle_timeout: self.opts.idle_timeout,
            out: self.out.clone(),
        };
        let sessions = self.sessions.clone();
        let http = self.http.clone();
        // The table lock is held across the spawn so the task cannot finish
        // (and try to remove itself) before its handle is inserted.
        let mut table = self.sessions.lock().expect("sessions lock");
        let task = tokio::spawn(async move {
            let ended = match entry.transport {
                Transport::Stdio => stdio::run(&ctx, &entry, rx, cancelled).await,
                Transport::Http => http::run(&ctx, &entry, http, rx, cancelled).await,
            };
            // `None`: the gateway closed it (or the connection went away)
            // and the table entry is already gone.
            let Some(why) = ended else { return };
            {
                let mut sessions = sessions.lock().expect("sessions lock");
                if sessions.get(&ctx.sid).is_some_and(|s| s.id == id) {
                    sessions.remove(&ctx.sid);
                }
            }
            info!(sid = %ctx.sid, server = %ctx.alias, reason = %why, "session ended");
            let close = Frame::SessionClose {
                sid: ctx.sid.clone(),
                reason: Some(why),
            };
            send_frame(&ctx.out, &close).await;
        });
        table.insert(
            sid,
            SessionHandle {
                id,
                alias: server,
                tx,
                cancel,
                task,
            },
        );
    }

    /// `mcp`: queue one message for the session's backend.
    pub async fn deliver(&mut self, sid: String, msg: Value) {
        let queued = {
            let sessions = self.sessions.lock().expect("sessions lock");
            sessions.get(&sid).map(|s| s.tx.try_send(msg))
        };
        match queued {
            Some(Ok(())) => {}
            Some(Err(mpsc::error::TrySendError::Full(_))) => {
                warn!(%sid, "backend is not keeping up; closing session");
                self.fail(&sid, reason::OVERLOADED).await;
            }
            // The backend task just ended and is reporting that itself.
            Some(Err(mpsc::error::TrySendError::Closed(_))) => {}
            None => {
                debug!(%sid, "mcp frame for an unknown session");
                self.refuse(&sid, reason::UNKNOWN_SESSION).await;
            }
        }
    }

    /// An `mcp` frame from the gateway exceeded [`MAX_GATEWAY_FRAME_BYTES`].
    pub async fn oversized(&mut self, sid: String) {
        warn!(%sid, limit = MAX_GATEWAY_FRAME_BYTES, "oversized mcp frame; closing session");
        self.fail(&sid, reason::MESSAGE_TOO_LARGE).await;
    }

    /// `session_close` from the gateway: tear the session down, no reply.
    pub async fn close(&mut self, sid: &str, why: Option<&str>) {
        match self.take(sid) {
            Some(handle) => {
                info!(%sid, server = %handle.alias, reason = why.unwrap_or(""), "session closed by gateway");
                stop(handle).await;
            }
            None => debug!(%sid, "session_close for an unknown session"),
        }
    }

    /// The attached set changed (config hot reload). Sessions on an alias
    /// that is gone end with `detached`, sessions on an alias whose entry
    /// differs in any field end with `reconfigured`; every other session is
    /// left alone. Later `session_open`s see the new set. The caller sends
    /// the fresh `servers` frame afterwards.
    pub async fn reconfigure(&mut self, backends: &[ServerEntry]) {
        let next: HashMap<String, ServerEntry> = backends
            .iter()
            .map(|e| (e.alias.clone(), e.clone()))
            .collect();
        let doomed: Vec<(SessionHandle, String, &'static str)> = {
            let mut sessions = self.sessions.lock().expect("sessions lock");
            let sids: Vec<(String, &'static str)> = sessions
                .iter()
                .filter_map(|(sid, s)| match next.get(&s.alias) {
                    None => Some((sid.clone(), reason::DETACHED)),
                    Some(entry) if self.backends.get(&s.alias) != Some(entry) => {
                        Some((sid.clone(), reason::RECONFIGURED))
                    }
                    Some(_) => None,
                })
                .collect();
            sids.into_iter()
                .filter_map(|(sid, why)| sessions.remove(&sid).map(|h| (h, sid, why)))
                .collect()
        };
        self.backends = next;
        for (handle, sid, why) in doomed {
            info!(%sid, server = %handle.alias, reason = why, "session ended by config reload");
            stop(handle).await;
            self.refuse(&sid, why).await;
        }
    }

    /// End every session (the connection is going away). Returns once all
    /// backends are stopped.
    pub async fn shutdown(&mut self) {
        let handles: Vec<SessionHandle> = {
            let mut sessions = self.sessions.lock().expect("sessions lock");
            sessions.drain().map(|(_, h)| h).collect()
        };
        if !handles.is_empty() {
            info!(sessions = handles.len(), "closing all sessions");
        }
        for handle in handles {
            stop(handle).await;
        }
    }

    fn take(&self, sid: &str) -> Option<SessionHandle> {
        self.sessions.lock().expect("sessions lock").remove(sid)
    }

    /// Tear down a live session and tell the gateway why.
    async fn fail(&mut self, sid: &str, why: &str) {
        if let Some(handle) = self.take(sid) {
            stop(handle).await;
        }
        self.refuse(sid, why).await;
    }

    async fn refuse(&self, sid: &str, why: &str) {
        let close = Frame::SessionClose {
            sid: sid.to_string(),
            reason: Some(why.to_string()),
        };
        send_frame(&self.out, &close).await;
    }
}

impl Drop for Relay {
    /// Safety net for a connection future that is dropped mid-flight
    /// (Ctrl-C): aborting a session task drops its child, which kills it.
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            for (_, handle) in sessions.drain() {
                handle.task.abort();
            }
        }
    }
}

/// Signal a session to stop and wait for its backend to be gone.
async fn stop(handle: SessionHandle) {
    let SessionHandle {
        tx,
        cancel,
        mut task,
        ..
    } = handle;
    drop((tx, cancel));
    if tokio::time::timeout(Duration::from_secs(5), &mut task)
        .await
        .is_err()
    {
        task.abort();
    }
}

async fn send_frame(out: &mpsc::Sender<Message>, frame: &Frame) -> bool {
    match frame.to_json() {
        Ok(text) => out.send(Message::text(text)).await.is_ok(),
        Err(e) => {
            warn!(error = %e, tag = frame.tag(), "could not serialize frame");
            true
        }
    }
}

/// Clip an error message for a `session_close.reason`.
pub(crate) fn short(msg: &str) -> String {
    const MAX: usize = 200;
    let line = msg.lines().next().unwrap_or("");
    match line.char_indices().nth(MAX) {
        Some((cut, _)) => format!("{}…", &line[..cut]),
        None => line.to_string(),
    }
}
