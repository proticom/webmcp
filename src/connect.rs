//! The relay connection: handshake, keep-alive and reconnect loop
//! (protocol §2).

use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{debug, info, warn};

use crate::config::ServerEntry;
use crate::keys;
use crate::platform;
use crate::proto::{
    connect_sign_message, Frame, ServerInfo, CLOSE_REVOKED, CLOSE_UNAUTHORIZED, PING, PONG,
    PROTOCOL_VERSION,
};
use crate::relay::{Relay, RelayOptions, MAX_GATEWAY_FRAME_BYTES};
use crate::reload::{ConfigWatcher, Pairing, DEFAULT_POLL_INTERVAL};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Frames queued for the writer task before senders wait.
const OUTBOUND_QUEUE: usize = 256;
/// Hard cap on one WebSocket message. Above it the connection is dropped;
/// `mcp` frames between [`MAX_GATEWAY_FRAME_BYTES`] and this only cost
/// their session.
const MAX_WS_MESSAGE_BYTES: usize = 4 * MAX_GATEWAY_FRAME_BYTES;
/// Close code 1012 ("service restart"); with [`CLOSE_REASON_REPLACED`] it
/// means another connection took this device's place.
const CLOSE_SERVICE_RESTART: u16 = 1012;
const CLOSE_REASON_REPLACED: &str = "replaced";
/// Floor for the socket write timeout (otherwise three ping intervals).
const MIN_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Everything one connection needs. Built by the CLI from the config, or
/// directly by tests.
#[derive(Clone)]
pub struct ConnectOptions {
    /// `wss://…/connect` (the `device_id` query is appended here).
    pub relay_url: String,
    pub device_id: String,
    pub signing_key: SigningKey,
    /// Advertised in the `servers` frame right after `welcome`, until a
    /// config reload replaces the set.
    pub servers: Vec<ServerInfo>,
    /// The servers actually relayed, looked up by alias on `session_open`.
    /// With `config_path` this is only the startup set.
    pub backends: Vec<ServerEntry>,
    /// Config file whose `servers` list is followed while connected
    /// (`attach`/`detach` take effect without a restart). `None` keeps the
    /// set above for good.
    pub config_path: Option<PathBuf>,
    /// How often `config_path` is checked for changes.
    pub config_poll_interval: Duration,
    /// Session limits and timeouts for the relay.
    pub relay: RelayOptions,
    /// Exit after the first `welcome` and one ping/pong round.
    pub once: bool,
    /// Keep-alive interval. Protocol says 30 s.
    pub ping_interval: Duration,
    /// Missed pongs before the connection is dropped. Protocol says 3.
    pub max_missed_pongs: u32,
    /// Timeout for each handshake step.
    pub handshake_timeout: Duration,
    /// Reconnect backoff bounds. Protocol says 1 s → 60 s.
    pub backoff_min: Duration,
    pub backoff_max: Duration,
}

impl ConnectOptions {
    /// Protocol defaults for a live gateway.
    pub fn new(relay_url: String, device_id: String, signing_key: SigningKey) -> Self {
        ConnectOptions {
            relay_url,
            device_id,
            signing_key,
            servers: Vec::new(),
            backends: Vec::new(),
            config_path: None,
            config_poll_interval: DEFAULT_POLL_INTERVAL,
            relay: RelayOptions::default(),
            once: false,
            ping_interval: Duration::from_secs(30),
            max_missed_pongs: 3,
            handshake_timeout: Duration::from_secs(15),
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
        }
    }

    /// The URL actually dialled: `relay_url?device_id=<id>`.
    pub fn dial_url(&self) -> Result<url::Url, ConnectError> {
        let mut u = url::Url::parse(&self.relay_url)
            .map_err(|e| ConnectError::BadUrl(format!("{}: {e}", self.relay_url)))?;
        u.query_pairs_mut()
            .append_pair("device_id", &self.device_id);
        Ok(u)
    }

    /// Advertise and relay exactly these servers.
    pub fn serve(&mut self, entries: &[ServerEntry]) {
        self.servers = entries.iter().map(ServerEntry::info).collect();
        self.backends = entries.to_vec();
    }

    /// The attached set as of startup, reloading from `config_path` if one
    /// is set. One watcher spans every reconnect of [`run`].
    fn watcher(&self) -> ConfigWatcher {
        ConfigWatcher::new(
            // `once` is over after one ping; nothing to follow.
            self.config_path.clone().filter(|_| !self.once),
            self.config_poll_interval,
            Pairing {
                device_id: self.device_id.clone(),
                relay_url: self.relay_url.clone(),
                verifying_key: self.signing_key.verifying_key(),
            },
            self.backends.clone(),
            self.servers.clone(),
        )
    }

    fn write_timeout(&self) -> Duration {
        (self.ping_interval * self.max_missed_pongs.max(1)).max(MIN_WRITE_TIMEOUT)
    }
}

/// Reasons a connection ended. `is_fatal` says whether the loop must stop.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("invalid relay url: {0}")]
    BadUrl(String),
    #[error(
        "the gateway rejected this device's key (close 4401); run `webmcp up --force` to pair again"
    )]
    Unauthorized,
    #[error("this device was revoked (close 4403); run `webmcp up --force` to pair again")]
    Revoked,
    #[error("the gateway does not know this device (HTTP 404 on connect); run `webmcp up --force` to pair again")]
    UnknownDevice,
    #[error("another webmcp instance connected as this device and took over (close 1012 \"replaced\"); this one is stopping")]
    Replaced,
    #[error("gateway closed the connection with code {code}: {reason}")]
    Closed { code: u16, reason: String },
    #[error("connection ended without a close frame")]
    Eof,
    #[error("protocol error during handshake: {0}")]
    Handshake(String),
    #[error("handshake timed out waiting for {0}")]
    Timeout(&'static str),
    #[error("{0} pongs missed; connection considered dead")]
    MissedPongs(u32),
    #[error("websocket error: {0}")]
    Ws(#[from] tungstenite::Error),
    #[error("could not serialize frame: {0}")]
    Json(#[from] serde_json::Error),
}

impl ConnectError {
    /// True when reconnecting cannot help: the user must pair again, or
    /// another instance owns the device now and reconnecting would only
    /// start a replace-and-be-replaced fight with it.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            ConnectError::Unauthorized
                | ConnectError::Revoked
                | ConnectError::UnknownDevice
                | ConnectError::Replaced
                | ConnectError::BadUrl(_)
        )
    }
}

/// What one successful session reported back.
#[derive(Debug, Clone, PartialEq)]
pub struct Welcome {
    pub handle: String,
    pub device: String,
    pub server_time: String,
}

/// Run the reconnect loop until a fatal error (or, with `once`, until the
/// first successful session completes). Non-fatal errors are logged and
/// retried with exponential backoff and jitter.
pub async fn run(opts: &ConnectOptions) -> Result<Welcome, ConnectError> {
    let mut attempt: u32 = 0;
    // Owned here, not by a connection: a reconnect advertises the set as
    // last reloaded, not the startup one.
    let mut watcher = opts.watcher();
    loop {
        match connection(opts, &mut watcher).await {
            Ok(w) if opts.once => return Ok(w),
            Ok(_) => {
                // Session ended cleanly (e.g. gateway restart): reconnect
                // quickly, starting the backoff over.
                attempt = 0;
            }
            Err(e) if e.is_fatal() => return Err(e),
            Err(e) => warn!(error = %e, "connection lost"),
        }
        let delay = backoff_delay(opts, attempt);
        attempt = attempt.saturating_add(1);
        info!(delay_ms = delay.as_millis() as u64, "reconnecting");
        tokio::time::sleep(delay).await;
    }
}

/// Exponential backoff with jitter: `min * 2^attempt` capped at `max`, then
/// randomized between half and full.
pub fn backoff_delay(opts: &ConnectOptions, attempt: u32) -> Duration {
    use rand::Rng;
    let exp = opts
        .backoff_min
        .checked_mul(1u32.checked_shl(attempt.min(31)).unwrap_or(u32::MAX))
        .unwrap_or(opts.backoff_max)
        .min(opts.backoff_max)
        .max(opts.backoff_min);
    let half = exp / 2;
    let jitter_ms = rand::thread_rng().gen_range(0..=half.as_millis() as u64);
    half + Duration::from_millis(jitter_ms)
}

/// One connection: dial, handshake, advertise servers, keep alive until the
/// connection ends. With `once`, returns right after the first pong.
pub async fn session(opts: &ConnectOptions) -> Result<Welcome, ConnectError> {
    connection(opts, &mut opts.watcher()).await
}

async fn connection(
    opts: &ConnectOptions,
    watcher: &mut ConfigWatcher,
) -> Result<Welcome, ConnectError> {
    let url = opts.dial_url()?;
    let mut request = url.as_str().into_client_request()?;
    request.headers_mut().insert(
        tungstenite::http::header::USER_AGENT,
        platform::user_agent().parse().expect("static user agent"),
    );
    debug!(%url, "dialling relay");
    let ws_config = WebSocketConfig::default().max_message_size(Some(MAX_WS_MESSAGE_BYTES));
    let dialled =
        tokio_tungstenite::connect_async_with_config(request, Some(ws_config), false).await;
    let (mut ws, _resp) = match dialled {
        Ok(ok) => ok,
        Err(tungstenite::Error::Http(resp)) if resp.status() == 404 => {
            return Err(ConnectError::UnknownDevice);
        }
        Err(e) => return Err(e.into()),
    };

    let welcome = match handshake(&mut ws, opts).await {
        Ok(w) => w,
        Err(e) => {
            let _ = ws.close(None).await;
            return Err(e);
        }
    };
    info!(handle = %welcome.handle, device = %welcome.device, "connected");

    // From here on the socket is split: one writer task fed by a bounded
    // channel (pings, relay frames), and this task reading.
    let (sink, mut stream) = ws.split();
    let (out, out_rx) = mpsc::channel::<Message>(OUTBOUND_QUEUE);
    let mut writer = tokio::spawn(write_loop(sink, out_rx, opts.write_timeout()));
    // Catch up on edits made while disconnected, so the first `servers`
    // frame is already current.
    watcher.poll();
    let mut relay = Relay::new(watcher.entries(), opts.relay.clone(), out.clone());

    let result = async {
        if !advertise(&out, watcher).await? {
            return Err(writer_error(&mut writer).await);
        }
        keepalive(&mut stream, &out, &mut writer, &mut relay, watcher, opts).await
    }
    .await;

    // The connection is over: every session ends with it.
    relay.shutdown().await;
    if opts.once && result.is_ok() {
        let close = Message::Close(Some(CloseFrame {
            code: CloseCode::Normal,
            reason: "once".into(),
        }));
        if out.send(close).await.is_ok() {
            let _ = tokio::time::timeout(opts.handshake_timeout, &mut writer).await;
        }
    }
    writer.abort();
    result.map(|_| welcome)
}

/// Queue a `servers` frame for the current attached set. `false` means the
/// writer is gone.
async fn advertise(
    out: &mpsc::Sender<Message>,
    watcher: &ConfigWatcher,
) -> Result<bool, ConnectError> {
    let servers = Frame::Servers {
        servers: watcher.infos().to_vec(),
    };
    Ok(out.send(Message::text(servers.to_json()?)).await.is_ok())
}

/// The writer half: drains the outbound queue into the socket until the
/// queue closes, a close frame went out, or a write fails or stalls.
async fn write_loop(
    mut sink: SplitSink<Ws, Message>,
    mut rx: mpsc::Receiver<Message>,
    write_timeout: Duration,
) -> Result<(), ConnectError> {
    while let Some(msg) = rx.recv().await {
        let closing = matches!(msg, Message::Close(_));
        match tokio::time::timeout(write_timeout, sink.send(msg)).await {
            Ok(sent) => sent?,
            Err(_) => return Err(ConnectError::Timeout("socket write")),
        }
        if closing {
            break;
        }
    }
    Ok(())
}

/// Why the writer task stopped. Only call once it is known to have ended
/// (its queue is closed).
async fn writer_error(writer: &mut JoinHandle<Result<(), ConnectError>>) -> ConnectError {
    match writer.await {
        Ok(Err(e)) => e,
        Ok(Ok(())) | Err(_) => ConnectError::Eof,
    }
}

/// `hello` → `challenge` → `auth` → `welcome`.
async fn handshake(ws: &mut Ws, opts: &ConnectOptions) -> Result<Welcome, ConnectError> {
    let hello = Frame::Hello {
        v: PROTOCOL_VERSION,
        device_id: opts.device_id.clone(),
        daemon_version: platform::VERSION.to_string(),
        platform: platform::platform(),
    };
    ws.send(Message::text(hello.to_json()?)).await?;

    let nonce = loop {
        match next_frame(ws, opts.handshake_timeout, "challenge").await? {
            Incoming::Frame(Frame::Challenge { nonce }) => break nonce,
            Incoming::Frame(Frame::Error { code, message }) => {
                warn!(%code, message = message.as_deref().unwrap_or(""), "gateway error before challenge");
                // The close that follows carries the real verdict.
            }
            Incoming::Frame(Frame::Unknown) | Incoming::Text(_) | Incoming::Oversized(_) => {}
            Incoming::Frame(other) => {
                return Err(ConnectError::Handshake(format!(
                    "expected challenge, got `{}`",
                    other.tag()
                )))
            }
            Incoming::Closed(e) => return Err(e),
        }
    };

    let msg = connect_sign_message(&opts.device_id, &nonce);
    let auth = Frame::Auth {
        signature: keys::sign_b64(&opts.signing_key, &msg),
    };
    ws.send(Message::text(auth.to_json()?)).await?;

    loop {
        match next_frame(ws, opts.handshake_timeout, "welcome").await? {
            Incoming::Frame(Frame::Welcome {
                handle,
                device,
                server_time,
            }) => {
                return Ok(Welcome {
                    handle,
                    device,
                    server_time,
                })
            }
            Incoming::Frame(Frame::Error { code, message }) => {
                warn!(%code, message = message.as_deref().unwrap_or(""), "gateway error before welcome");
                if code == "unauthorized" {
                    // Spec: error{unauthorized} is followed by close 4401.
                    // Wait for it, but treat a plain EOF as the same verdict.
                    return match next_frame(ws, opts.handshake_timeout, "close").await {
                        Ok(Incoming::Closed(ConnectError::Eof)) | Err(_) => {
                            Err(ConnectError::Unauthorized)
                        }
                        Ok(Incoming::Closed(e)) => Err(e),
                        Ok(_) => Err(ConnectError::Unauthorized),
                    };
                }
            }
            Incoming::Frame(Frame::Unknown) | Incoming::Text(_) | Incoming::Oversized(_) => {}
            Incoming::Frame(other) => {
                return Err(ConnectError::Handshake(format!(
                    "expected welcome, got `{}`",
                    other.tag()
                )))
            }
            Incoming::Closed(e) => return Err(e),
        }
    }
}

/// Send `ping` on an interval, count missed `pong`s, dispatch other frames,
/// and follow config reloads.
async fn keepalive(
    stream: &mut SplitStream<Ws>,
    out: &mpsc::Sender<Message>,
    writer: &mut JoinHandle<Result<(), ConnectError>>,
    relay: &mut Relay,
    watcher: &mut ConfigWatcher,
    opts: &ConnectOptions,
) -> Result<(), ConnectError> {
    let mut ticker = tokio::time::interval(opts.ping_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // In `once` mode the first tick (immediate) sends the ping right away;
    // otherwise skip it so the first ping goes out after one full interval.
    if !opts.once {
        ticker.tick().await;
    }
    let mut awaiting_pong = false;
    let mut missed: u32 = 0;
    let mut pongs: u64 = 0;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if awaiting_pong {
                    missed += 1;
                    warn!(missed, "pong missed");
                    if missed >= opts.max_missed_pongs {
                        return Err(ConnectError::MissedPongs(missed));
                    }
                }
                if out.send(Message::text(PING)).await.is_err() {
                    return Err(writer_error(writer).await);
                }
                awaiting_pong = true;
            }
            _ = watcher.changed() => {
                // Affected sessions close first, then the new set goes out,
                // in that order on the wire.
                relay.reconfigure(watcher.entries()).await;
                for s in watcher.infos().iter().filter(|s| s.error.is_some()) {
                    warn!(server = %s.alias, "{}", s.error.as_deref().unwrap_or(""));
                }
                if !advertise(out, watcher).await? {
                    return Err(writer_error(writer).await);
                }
            }
            ended = &mut *writer => {
                return Err(match ended {
                    Ok(Err(e)) => e,
                    Ok(Ok(())) | Err(_) => ConnectError::Eof,
                });
            }
            incoming = stream.next() => {
                match classify(incoming)? {
                    Incoming::Text(t) if t == PONG => {
                        awaiting_pong = false;
                        missed = 0;
                        pongs += 1;
                        debug!(pongs, "pong");
                        if opts.once {
                            return Ok(());
                        }
                    }
                    Incoming::Text(t) => debug!(text = %t, "ignoring non-JSON text frame"),
                    Incoming::Frame(frame) => handle_frame(frame, relay, opts).await,
                    Incoming::Oversized(sid) => relay.oversized(sid).await,
                    Incoming::Closed(e) => return Err(e),
                }
            }
        }
    }
}

/// Post-welcome frame dispatch: session frames go to the relay.
async fn handle_frame(frame: Frame, relay: &mut Relay, opts: &ConnectOptions) {
    match frame {
        Frame::Error { code, message } => {
            warn!(%code, message = message.as_deref().unwrap_or(""), "gateway error");
        }
        Frame::SessionOpen {
            sid,
            server,
            client,
        } => relay.open(sid, server, client).await,
        Frame::SessionClose { sid, reason } => relay.close(&sid, reason.as_deref()).await,
        Frame::Mcp { sid, msg } => relay.deliver(sid, msg).await,
        Frame::Detach { alias } => remote_detach(&alias, opts),
        Frame::Unknown => debug!("ignoring unknown frame"),
        other => debug!(tag = other.tag(), "ignoring unexpected frame after welcome"),
    }
}

/// The owner removed a server on the dashboard: drop it from the config file.
/// The config watcher then ends its sessions and re-advertises, exactly as it
/// does for a local `webmcp detach`.
fn remote_detach(alias: &str, opts: &ConnectOptions) {
    let Some(path) = opts.config_path.as_deref() else {
        debug!(%alias, "detach requested but this connection has no config file");
        return;
    };
    let Some(dir) = path.parent() else { return };
    let result = crate::config::Config::load_path(path).and_then(|mut cfg| {
        cfg.detach(alias)?;
        cfg.save_to(dir)
    });
    match result {
        Ok(()) => info!(%alias, "detached at the owner's request from the dashboard"),
        Err(crate::error::Error::NoSuchAlias(_)) => debug!(%alias, "detach: already gone"),
        Err(e) => warn!(%alias, error = %e, "could not apply remote detach"),
    }
}

enum Incoming {
    Frame(Frame),
    /// A text frame that is not JSON (e.g. `pong`).
    Text(String),
    /// An `mcp` frame over [`MAX_GATEWAY_FRAME_BYTES`]; carries its `sid`.
    Oversized(String),
    Closed(ConnectError),
}

fn classify(item: Option<Result<Message, tungstenite::Error>>) -> Result<Incoming, ConnectError> {
    let msg = match item {
        None => return Ok(Incoming::Closed(ConnectError::Eof)),
        Some(Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed)) => {
            return Ok(Incoming::Closed(ConnectError::Eof))
        }
        Some(Err(e)) => return Err(e.into()),
        Some(Ok(m)) => m,
    };
    Ok(match msg {
        Message::Text(text) => {
            let text = text.as_str();
            if text.trim_start().starts_with('{') {
                match Frame::from_json(text) {
                    Ok(Frame::Mcp { sid, .. }) if text.len() > MAX_GATEWAY_FRAME_BYTES => {
                        Incoming::Oversized(sid)
                    }
                    Ok(f) => Incoming::Frame(f),
                    Err(e) => {
                        debug!(error = %e, "ignoring malformed frame");
                        Incoming::Frame(Frame::Unknown)
                    }
                }
            } else {
                Incoming::Text(text.to_string())
            }
        }
        Message::Close(frame) => Incoming::Closed(close_error(frame)),
        // Binary is not part of v1; ping/pong control frames are answered by
        // tungstenite itself.
        Message::Binary(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {
            Incoming::Frame(Frame::Unknown)
        }
    })
}

fn close_error(frame: Option<CloseFrame>) -> ConnectError {
    let Some(frame) = frame else {
        return ConnectError::Eof;
    };
    let code: u16 = frame.code.into();
    match code {
        CLOSE_UNAUTHORIZED => ConnectError::Unauthorized,
        CLOSE_REVOKED => ConnectError::Revoked,
        // The gateway keeps one socket per device and hands it to the newest
        // authenticated connection. Only this exact pair means that: a plain
        // 1012 is a gateway restart and is retried.
        CLOSE_SERVICE_RESTART if frame.reason.as_str() == CLOSE_REASON_REPLACED => {
            ConnectError::Replaced
        }
        _ => ConnectError::Closed {
            code,
            reason: frame.reason.to_string(),
        },
    }
}

async fn next_frame(
    ws: &mut Ws,
    timeout: Duration,
    what: &'static str,
) -> Result<Incoming, ConnectError> {
    match tokio::time::timeout(timeout, ws.next()).await {
        Ok(item) => classify(item),
        Err(_) => Err(ConnectError::Timeout(what)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> ConnectOptions {
        ConnectOptions::new(
            "wss://webmcp.fast/connect".into(),
            "dev_0123456789abcdef".into(),
            keys::generate(),
        )
    }

    #[test]
    fn dial_url_appends_device_id() {
        assert_eq!(
            opts().dial_url().unwrap().as_str(),
            "wss://webmcp.fast/connect?device_id=dev_0123456789abcdef"
        );
    }

    #[test]
    fn backoff_is_bounded_and_grows() {
        let o = opts();
        for attempt in 0..40 {
            let d = backoff_delay(&o, attempt);
            let exp = Duration::from_secs(1 << attempt.min(6));
            let cap = exp.min(o.backoff_max);
            assert!(d >= cap / 2 && d <= cap, "attempt {attempt}: {d:?}");
        }
        assert!(backoff_delay(&o, 0) >= Duration::from_millis(500));
        assert!(backoff_delay(&o, 100) <= Duration::from_secs(60));
    }

    #[test]
    fn close_codes_map() {
        let mk = |code: u16| {
            close_error(Some(CloseFrame {
                code: CloseCode::from(code),
                reason: "".into(),
            }))
        };
        assert!(matches!(mk(4401), ConnectError::Unauthorized));
        assert!(matches!(mk(4403), ConnectError::Revoked));
        assert!(matches!(mk(1001), ConnectError::Closed { code: 1001, .. }));
        assert!(mk(4401).is_fatal());
        assert!(mk(4403).is_fatal());
        assert!(!mk(1001).is_fatal());
        assert!(matches!(close_error(None), ConnectError::Eof));
    }

    #[test]
    fn replaced_is_fatal_but_a_plain_restart_is_not() {
        let mk = |code: u16, reason: &str| {
            close_error(Some(CloseFrame {
                code: CloseCode::from(code),
                reason: reason.to_string().into(),
            }))
        };
        let replaced = mk(1012, "replaced");
        assert!(matches!(replaced, ConnectError::Replaced));
        assert!(replaced.is_fatal());
        let restart = mk(1012, "");
        assert!(matches!(restart, ConnectError::Closed { code: 1012, .. }));
        assert!(!restart.is_fatal());
        assert!(!mk(1000, "replaced").is_fatal());
    }
}
