//! http backend: the daemon is an MCP Streamable HTTP *client* of a local
//! endpoint. Every gateway message is one POST; the answer is a JSON body,
//! an SSE stream or `202`. Requests of one session run concurrently.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::{HeaderValue, ACCEPT, CONTENT_TYPE};
use reqwest::StatusCode;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tracing::{debug, warn};

use super::sse::SseParser;
use super::{reason, short, SessionCtx, MAX_BACKEND_MESSAGE_BYTES};
use crate::config::ServerEntry;

const SESSION_HEADER: &str = "mcp-session-id";
const VERSION_HEADER: &str = "mcp-protocol-version";
const EVENT_STREAM: &str = "text/event-stream";
/// Budget for the best-effort `DELETE` on close.
const DELETE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, thiserror::Error)]
enum UpstreamError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("upstream answered HTTP {0}")]
    Status(StatusCode),
    #[error("upstream message exceeds {MAX_BACKEND_MESSAGE_BYTES} bytes")]
    TooLarge,
    #[error("relay connection is gone")]
    Disconnected,
}

impl UpstreamError {
    fn close_reason(&self) -> &'static str {
        match self {
            UpstreamError::TooLarge => reason::MESSAGE_TOO_LARGE,
            _ => reason::SERVER_EXITED,
        }
    }
}

/// Per-session upstream state shared by the concurrent requests.
struct Upstream {
    client: reqwest::Client,
    url: String,
    /// `Mcp-Session-Id` from the initialize response, echoed afterwards.
    session_id: Mutex<Option<HeaderValue>>,
    /// `protocolVersion` from the initialize result, echoed afterwards.
    protocol_version: Mutex<Option<HeaderValue>>,
    last_activity: Mutex<Instant>,
}

impl Upstream {
    fn request(&self, method: reqwest::Method) -> reqwest::RequestBuilder {
        let mut req = self.client.request(method, &self.url);
        if let Some(id) = self.session_id.lock().expect("lock").clone() {
            req = req.header(SESSION_HEADER, id);
        }
        if let Some(v) = self.protocol_version.lock().expect("lock").clone() {
            req = req.header(VERSION_HEADER, v);
        }
        req
    }

    fn touch(&self) {
        *self.last_activity.lock().expect("lock") = Instant::now();
    }
}

/// What one finished task of the session's set was.
enum Done {
    Post,
    /// The `initialize` exchange finished; the listening stream may open.
    Initialized,
    Listener,
    Fatal(UpstreamError),
}

/// Run one session. Returns the `session_close` reason to report, or `None`
/// when the gateway side closed it.
pub(super) async fn run(
    ctx: &SessionCtx,
    entry: &ServerEntry,
    client: reqwest::Client,
    mut rx: mpsc::Receiver<Value>,
    mut cancelled: oneshot::Receiver<()>,
) -> Option<String> {
    let Some(url) = entry.url.clone() else {
        return Some(format!("{}: no url configured", reason::SPAWN_FAILED));
    };
    let up = Arc::new(Upstream {
        client,
        url,
        session_id: Mutex::new(None),
        protocol_version: Mutex::new(None),
        last_activity: Mutex::new(Instant::now()),
    });
    let ctx = Arc::new(ctx.clone());
    let mut tasks: JoinSet<Done> = JoinSet::new();
    let mut in_flight: usize = 0;
    let mut deadline = Instant::now() + ctx.idle_timeout;

    let why = loop {
        tokio::select! {
            _ = &mut cancelled => break None,
            inbound = rx.recv() => {
                let Some(msg) = inbound else { break None };
                up.touch();
                let is_init = msg.get("method").and_then(Value::as_str) == Some("initialize");
                if is_init {
                    // Later requests must carry the session id this one
                    // returns, so wait for its headers before reading on.
                    let sent = tokio::select! {
                        sent = send(&up, &msg) => sent,
                        _ = &mut cancelled => break None,
                    };
                    let resp = match sent {
                        Ok(resp) => resp,
                        Err(e) => break Some(fatal(&ctx, &e)),
                    };
                    let (ctx, up) = (ctx.clone(), up.clone());
                    tasks.spawn(async move {
                        match consume(&ctx, &up, resp, true).await {
                            Ok(()) => Done::Initialized,
                            Err(e) => Done::Fatal(e),
                        }
                    });
                } else {
                    let (ctx, up) = (ctx.clone(), up.clone());
                    tasks.spawn(async move {
                        let result = match send(&up, &msg).await {
                            Ok(resp) => consume(&ctx, &up, resp, false).await,
                            Err(e) => Err(e),
                        };
                        result.map_or_else(Done::Fatal, |()| Done::Post)
                    });
                }
                in_flight += 1;
            }
            Some(done) = tasks.join_next() => match done {
                Ok(Done::Post) => in_flight -= 1,
                Ok(Done::Initialized) => {
                    in_flight -= 1;
                    let (ctx, up) = (ctx.clone(), up.clone());
                    tasks.spawn(async move {
                        listen(&ctx, &up).await;
                        Done::Listener
                    });
                }
                Ok(Done::Listener) => {}
                Ok(Done::Fatal(e)) => break Some(fatal(&ctx, &e)),
                Err(e) => {
                    warn!(sid = %ctx.sid, error = %e, "upstream task failed");
                    break Some(reason::SERVER_EXITED.to_string());
                }
            },
            _ = tokio::time::sleep_until(deadline) => {
                // A request still running counts as traffic.
                let quiet_since = if in_flight > 0 {
                    Instant::now()
                } else {
                    *up.last_activity.lock().expect("lock")
                };
                deadline = quiet_since + ctx.idle_timeout;
                if deadline <= Instant::now() {
                    break Some(reason::IDLE.to_string());
                }
            }
        }
    };

    tasks.shutdown().await;
    terminate(&ctx, &up).await;
    why
}

fn fatal(ctx: &SessionCtx, e: &UpstreamError) -> String {
    warn!(sid = %ctx.sid, server = %ctx.alias, error = %short(&e.to_string()), "upstream failed");
    e.close_reason().to_string()
}

/// POST one message; resolves once the response headers are in.
async fn send(up: &Upstream, msg: &Value) -> Result<reqwest::Response, UpstreamError> {
    let resp = up
        .request(reqwest::Method::POST)
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json, text/event-stream")
        .json(msg)
        .send()
        .await?;
    if let Some(id) = resp.headers().get(SESSION_HEADER) {
        let mut session_id = up.session_id.lock().expect("lock");
        if session_id.is_none() {
            *session_id = Some(id.clone());
        }
    }
    Ok(resp)
}

/// Relay everything a POST response carries.
async fn consume(
    ctx: &SessionCtx,
    up: &Upstream,
    resp: reqwest::Response,
    is_init: bool,
) -> Result<(), UpstreamError> {
    let status = resp.status();
    if is_event_stream(&resp) && status.is_success() {
        return stream(ctx, up, resp, is_init).await;
    }
    let body = read_body(resp).await?;
    let parsed = serde_json::from_slice::<Value>(&body).ok();
    if !status.is_success() {
        // A JSON-RPC error in the body is an answer; anything else means
        // the upstream (or its session) is gone.
        return match parsed {
            Some(msg) if msg.get("jsonrpc").is_some() => emit(ctx, up, msg, false).await,
            _ => Err(UpstreamError::Status(status)),
        };
    }
    match parsed {
        // Pre-2025-06-18 servers may answer with a batch.
        Some(Value::Array(batch)) => {
            for msg in batch {
                emit(ctx, up, msg, is_init).await?;
            }
        }
        Some(msg) => emit(ctx, up, msg, is_init).await?,
        // `202 Accepted` and friends: nothing to relay.
        None if body.iter().all(u8::is_ascii_whitespace) => {}
        None => {
            debug!(sid = %ctx.sid, server = %ctx.alias, %status, "ignoring non-JSON response body")
        }
    }
    Ok(())
}

/// Relay an SSE body event by event, as the events arrive.
async fn stream(
    ctx: &SessionCtx,
    up: &Upstream,
    mut resp: reqwest::Response,
    is_init: bool,
) -> Result<(), UpstreamError> {
    let mut parser = SseParser::default();
    while let Some(chunk) = resp.chunk().await? {
        for data in parser.push(&chunk) {
            match serde_json::from_str::<Value>(&data) {
                Ok(msg) => emit(ctx, up, msg, is_init).await?,
                Err(e) => debug!(sid = %ctx.sid, error = %e, "ignoring non-JSON SSE event"),
            }
        }
        if parser.buffered() > MAX_BACKEND_MESSAGE_BYTES {
            return Err(UpstreamError::TooLarge);
        }
    }
    Ok(())
}

async fn emit(
    ctx: &SessionCtx,
    up: &Upstream,
    msg: Value,
    is_init: bool,
) -> Result<(), UpstreamError> {
    if is_init {
        let version = msg
            .pointer("/result/protocolVersion")
            .and_then(Value::as_str)
            .and_then(|v| HeaderValue::from_str(v).ok());
        if let Some(version) = version {
            *up.protocol_version.lock().expect("lock") = Some(version);
        }
    }
    up.touch();
    if ctx.emit(msg).await {
        Ok(())
    } else {
        Err(UpstreamError::Disconnected)
    }
}

/// The optional `GET` stream for server-initiated messages. Servers that
/// do not offer one answer `405`; any failure here is silent and the
/// stream is not reopened.
async fn listen(ctx: &SessionCtx, up: &Upstream) {
    let resp = up
        .request(reqwest::Method::GET)
        .header(ACCEPT, EVENT_STREAM)
        .send()
        .await;
    let resp = match resp {
        Ok(resp) if resp.status().is_success() && is_event_stream(&resp) => resp,
        Ok(resp) => {
            debug!(sid = %ctx.sid, server = %ctx.alias, status = %resp.status(), "no listening stream");
            return;
        }
        Err(e) => {
            debug!(sid = %ctx.sid, error = %e, "listening stream failed");
            return;
        }
    };
    debug!(sid = %ctx.sid, server = %ctx.alias, "listening stream open");
    if let Err(e) = stream(ctx, up, resp, false).await {
        debug!(sid = %ctx.sid, error = %e, "listening stream ended");
    }
}

/// Best-effort `DELETE` so the upstream can free its session.
async fn terminate(ctx: &SessionCtx, up: &Upstream) {
    if up.session_id.lock().expect("lock").is_none() {
        return;
    }
    let req = up.request(reqwest::Method::DELETE).send();
    match tokio::time::timeout(DELETE_TIMEOUT, req).await {
        Ok(Ok(resp)) => debug!(sid = %ctx.sid, status = %resp.status(), "upstream session deleted"),
        Ok(Err(e)) => debug!(sid = %ctx.sid, error = %e, "upstream session delete failed"),
        Err(_) => debug!(sid = %ctx.sid, "upstream session delete timed out"),
    }
}

fn is_event_stream(resp: &reqwest::Response) -> bool {
    resp.headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.trim_start()
                .to_ascii_lowercase()
                .starts_with(EVENT_STREAM)
        })
}

async fn read_body(mut resp: reqwest::Response) -> Result<Vec<u8>, UpstreamError> {
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_BACKEND_MESSAGE_BYTES {
            return Err(UpstreamError::TooLarge);
        }
    }
    Ok(body)
}
