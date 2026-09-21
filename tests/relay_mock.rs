//! Drive the M2 relay end to end: a scriptable in-process mock gateway on
//! one side, a fake stdio MCP server (a `sh` script) or an in-process HTTP
//! MCP endpoint on the other. No network, no npx.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use webmcp_daemon::config::{Config, ServerEntry};
use webmcp_daemon::connect::{self, ConnectOptions};
use webmcp_daemon::keys;
use webmcp_daemon::proto::{
    connect_sign_message, ClientInfo, Frame, ServerStatus, SessionMode, PING, PONG,
};

const DEVICE_ID: &str = "dev_0123456789abcdef";
const WAIT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------- gateway

enum Cmd {
    Send(Frame),
    /// Raw text, for frames `Frame` cannot express (oversized ones).
    SendText(String),
    /// Cut the TCP connection without a close frame.
    Drop,
}

struct Gateway {
    url: String,
    cmd: mpsc::UnboundedSender<Cmd>,
    frames: mpsc::UnboundedReceiver<Frame>,
}

impl Gateway {
    fn send(&self, frame: Frame) {
        self.cmd.send(Cmd::Send(frame)).unwrap();
    }

    fn open(&self, sid: &str, server: &str) {
        self.send(Frame::SessionOpen {
            sid: sid.into(),
            server: server.into(),
            client: Some(ClientInfo {
                name: Some("test-harness".into()),
                version: Some("1.0".into()),
                extra: Default::default(),
            }),
        });
    }

    fn mcp(&self, sid: &str, msg: Value) {
        self.send(Frame::Mcp {
            sid: sid.into(),
            msg,
        });
    }

    fn close(&self, sid: &str) {
        self.send(Frame::SessionClose {
            sid: sid.into(),
            reason: Some("client_gone".into()),
        });
    }

    /// Next frame from the daemon (pings are answered inside the mock).
    async fn recv(&mut self) -> Frame {
        tokio::time::timeout(WAIT, self.frames.recv())
            .await
            .expect("timed out waiting for a frame from the daemon")
            .expect("gateway task ended")
    }

    /// Next `mcp` frame; anything else is a test failure.
    async fn recv_mcp(&mut self, sid: &str) -> Value {
        match self.recv().await {
            Frame::Mcp { sid: got, msg } => {
                assert_eq!(got, sid);
                msg
            }
            other => panic!("expected mcp for {sid}, got {other:?}"),
        }
    }

    async fn recv_close(&mut self, sid: &str) -> String {
        match self.recv().await {
            Frame::SessionClose { sid: got, reason } => {
                assert_eq!(got, sid);
                reason.unwrap_or_default()
            }
            other => panic!("expected session_close for {sid}, got {other:?}"),
        }
    }
}

/// A mock gateway serving one daemon connection at a time, forever.
async fn start_gateway(trusted: VerifyingKey) -> Gateway {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let (frame_tx, frame_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            serve(stream, trusted, &mut cmd_rx, &frame_tx).await;
        }
    });
    Gateway {
        url: format!("ws://{addr}/connect"),
        cmd: cmd_tx,
        frames: frame_rx,
    }
}

async fn serve(
    stream: TcpStream,
    trusted: VerifyingKey,
    cmds: &mut mpsc::UnboundedReceiver<Cmd>,
    frames: &mpsc::UnboundedSender<Frame>,
) {
    let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
    let text = |f: Frame| Message::text(f.to_json().unwrap());

    // hello → challenge → auth → welcome
    let Some(Ok(Message::Text(hello))) = ws.next().await else {
        return;
    };
    assert!(matches!(
        Frame::from_json(hello.as_str()),
        Ok(Frame::Hello { v: 1, .. })
    ));
    let nonce = B64.encode(rand::random::<[u8; 32]>());
    ws.send(text(Frame::Challenge {
        nonce: nonce.clone(),
    }))
    .await
    .unwrap();
    let Some(Ok(Message::Text(auth))) = ws.next().await else {
        return;
    };
    let Ok(Frame::Auth { signature }) = Frame::from_json(auth.as_str()) else {
        panic!("expected auth");
    };
    let sig = Signature::from_slice(&B64.decode(signature).unwrap()).unwrap();
    trusted
        .verify(&connect_sign_message(DEVICE_ID, &nonce), &sig)
        .expect("daemon signature verifies");
    ws.send(text(Frame::Welcome {
        handle: "alice".into(),
        device: "macbook".into(),
        server_time: "2026-09-19T21:00:00Z".into(),
    }))
    .await
    .unwrap();

    loop {
        tokio::select! {
            cmd = cmds.recv() => match cmd {
                Some(Cmd::Send(frame)) => ws.send(text(frame)).await.unwrap(),
                Some(Cmd::SendText(raw)) => ws.send(Message::text(raw)).await.unwrap(),
                Some(Cmd::Drop) | None => return,
            },
            msg = ws.next() => match msg {
                Some(Ok(Message::Text(t))) if t.as_str() == PING => {
                    ws.send(Message::text(PONG)).await.unwrap();
                }
                Some(Ok(Message::Text(t))) => {
                    let _ = frames.send(Frame::from_json(t.as_str()).unwrap());
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return,
            },
        }
    }
}

/// The daemon under test; aborted (sessions and all) when dropped.
struct Daemon(JoinHandle<()>);

impl Drop for Daemon {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn start(
    entries: Vec<ServerEntry>,
    tweak: impl FnOnce(&mut ConnectOptions),
) -> (Gateway, Daemon) {
    let key = keys::generate();
    let mut gw = start_gateway(key.verifying_key()).await;
    let mut opts = ConnectOptions::new(gw.url.clone(), DEVICE_ID.to_string(), key);
    opts.ping_interval = Duration::from_millis(100);
    opts.backoff_min = Duration::from_millis(10);
    opts.backoff_max = Duration::from_millis(50);
    opts.serve(&entries);
    tweak(&mut opts);
    let daemon = Daemon(tokio::spawn(async move {
        let _ = connect::run(&opts).await;
    }));
    // Every connection starts with the `servers` frame.
    match gw.recv().await {
        Frame::Servers { servers } => assert_eq!(servers.len(), entries.len()),
        other => panic!("expected servers, got {other:?}"),
    }
    (gw, daemon)
}

// ------------------------------------------------------ fake stdio server

/// A line-oriented fake MCP server. Records its pid, environment and cwd in
/// `$FAKE_DIR` so tests can check what was spawned and that it died. Its
/// first argument, if any, becomes the `serverInfo.name`.
const FAKE_SERVER: &str = r#"#!/bin/sh
name=${1:-fake}
echo $$ >> "$FAKE_DIR/pids"
echo "$FAKE_GREETING" > "$FAKE_DIR/greeting"
pwd > "$FAKE_DIR/cwd"
echo "fake server up" >&2
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$line" in
    *'"initialize"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"%s","version":"0.0.1"}}}\n' "$id" "$name" ;;
    *'"tools/list"'*)
      printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}}\n' "$id" ;;
    *'"test/exit"'*)
      exit 3 ;;
    *'"id"'*)
      echo "this line is not json"
      printf '{"jsonrpc":"2.0","id":%s,"result":{"echo":%s}}\n' "$id" "$line" ;;
  esac
done
"#;

struct FakeServer {
    dir: tempfile::TempDir,
}

impl FakeServer {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("server.sh"), FAKE_SERVER).unwrap();
        std::fs::create_dir(dir.path().join("work")).unwrap();
        FakeServer { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn entry(&self, alias: &str, mode: SessionMode) -> ServerEntry {
        self.named_entry(alias, mode, None)
    }

    /// Like [`Self::entry`], with a different command line: the extra
    /// argument shows up as the `serverInfo.name`.
    fn named_entry(&self, alias: &str, mode: SessionMode, name: Option<&str>) -> ServerEntry {
        let script = self.path("server.sh");
        let argv = ["sh", script.to_str().unwrap()].into_iter().chain(name);
        let command = shell_words::join(argv);
        let mut e = ServerEntry::stdio(alias, &command, mode).unwrap();
        let dir = self.dir.path().to_str().unwrap().to_string();
        e.env.insert("FAKE_DIR".into(), dir);
        e.env
            .insert("FAKE_GREETING".into(), "hello from env".into());
        e.cwd = Some(self.path("work"));
        e
    }

    /// Pids of every instance spawned so far, once `n` have started.
    async fn pids(&self, n: usize) -> Vec<u32> {
        let file = self.path("pids");
        eventually("fake server to start", || {
            let pids: Vec<u32> = std::fs::read_to_string(&file)
                .unwrap_or_default()
                .lines()
                .filter_map(|l| l.trim().parse().ok())
                .collect();
            (pids.len() >= n).then_some(pids)
        })
        .await
    }
}

fn alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap()
        .success()
}

async fn eventually<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if let Some(v) = check() {
            return v;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn assert_dies(pid: u32) {
    eventually("the child to be killed", || (!alive(pid)).then_some(())).await;
}

fn initialize(id: u64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{
        "protocolVersion":"2025-06-18","capabilities":{},
        "clientInfo":{"name":"test-harness","version":"1.0"}}})
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap().trim().to_string()
}

// ------------------------------------------------------------ stdio tests

#[tokio::test]
async fn stdio_session_relays_and_close_kills_the_child() {
    let fake = FakeServer::new();
    let (mut gw, _daemon) = start(vec![fake.entry("fs", SessionMode::PerSession)], |_| {}).await;

    // No ack for session_open: the mcp frames follow immediately and must
    // be queued until the process is up.
    gw.open("ses_1", "fs");
    gw.mcp("ses_1", initialize(1));
    gw.mcp(
        "ses_1",
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    gw.mcp(
        "ses_1",
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    );

    let init = gw.recv_mcp("ses_1").await;
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["serverInfo"]["name"], "fake");
    let tools = gw.recv_mcp("ses_1").await;
    assert_eq!(tools["id"], 2);
    assert_eq!(tools["result"]["tools"][0]["name"], "echo");

    // Verbatim both ways; the non-JSON stdout line in between is dropped.
    let call = json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"echo","arguments":{"text":"héllo \"quoted\"\nnewline"}}});
    gw.mcp("ses_1", call.clone());
    let echoed = gw.recv_mcp("ses_1").await;
    assert_eq!(echoed["id"], 3);
    assert_eq!(echoed["result"]["echo"], call);

    // env and cwd from the server entry reached the process.
    assert_eq!(read(&fake.path("greeting")), "hello from env");
    assert!(read(&fake.path("cwd")).ends_with("/work"));

    let pid = fake.pids(1).await[0];
    assert!(alive(pid));
    gw.close("ses_1");
    assert_dies(pid).await;

    // The sid is gone: a late mcp frame is answered with a close, and the
    // daemon never echoed a session_close for the gateway's own close.
    gw.mcp("ses_1", json!({"jsonrpc":"2.0","id":4,"method":"ping"}));
    assert_eq!(gw.recv_close("ses_1").await, "unknown_session");
}

#[tokio::test]
async fn per_session_servers_get_one_process_each_and_exit_is_reported() {
    let fake = FakeServer::new();
    let (mut gw, _daemon) = start(vec![fake.entry("fs", SessionMode::PerSession)], |_| {}).await;
    gw.open("ses_a", "fs");
    gw.mcp("ses_a", initialize(1));
    assert_eq!(gw.recv_mcp("ses_a").await["id"], 1);
    gw.open("ses_b", "fs");
    gw.mcp("ses_b", initialize(1));
    assert_eq!(gw.recv_mcp("ses_b").await["id"], 1);
    let pids = fake.pids(2).await;
    assert_ne!(pids[0], pids[1]);

    // The server behind ses_a exits on its own.
    gw.mcp("ses_a", json!({"jsonrpc":"2.0","method":"test/exit"}));
    assert_eq!(gw.recv_close("ses_a").await, "server_exited");
    assert_dies(pids[0]).await;

    // ses_b is untouched.
    gw.mcp(
        "ses_b",
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    );
    assert_eq!(gw.recv_mcp("ses_b").await["id"], 2);
}

#[tokio::test]
async fn refusals_unknown_busy_limit_unsupported_and_spawn_failure() {
    let fake = FakeServer::new();
    let mut limited = fake.entry("limited", SessionMode::PerSession);
    limited.max_sessions = Some(1);
    let entries = vec![
        fake.entry("browser", SessionMode::Exclusive),
        limited,
        fake.entry("muxed", SessionMode::Shared),
        ServerEntry::stdio(
            "broken",
            "/nonexistent/webmcp-fake-server --x",
            SessionMode::PerSession,
        )
        .unwrap(),
    ];
    let key = keys::generate();
    let mut gw = start_gateway(key.verifying_key()).await;
    let mut opts = ConnectOptions::new(gw.url.clone(), DEVICE_ID.to_string(), key);
    opts.serve(&entries);
    let _daemon = Daemon(tokio::spawn(async move {
        let _ = connect::run(&opts).await;
    }));
    // Shared stdio is advertised as an error, everything else as ready.
    let Frame::Servers { servers } = gw.recv().await else {
        panic!("expected servers");
    };
    for s in &servers {
        let expect = if s.alias == "muxed" {
            ServerStatus::Error
        } else {
            ServerStatus::Ready
        };
        assert_eq!(s.status, expect, "{}", s.alias);
    }
    assert_eq!(
        servers[2].error.as_deref(),
        Some("shared mode over stdio is not supported yet; use per-session")
    );

    gw.open("ses_x", "nope");
    assert_eq!(gw.recv_close("ses_x").await, "unknown_server");

    gw.open("ses_m", "muxed");
    assert_eq!(gw.recv_close("ses_m").await, "unsupported_mode");

    gw.open("ses_f", "broken");
    let why = gw.recv_close("ses_f").await;
    assert!(why.starts_with("spawn_failed: "), "{why}");

    // exclusive: the second session is refused while the first lives …
    gw.open("ses_1", "browser");
    gw.mcp("ses_1", initialize(1));
    assert_eq!(gw.recv_mcp("ses_1").await["id"], 1);
    gw.open("ses_2", "browser");
    assert_eq!(gw.recv_close("ses_2").await, "busy");
    // … and admitted once it is closed.
    gw.close("ses_1");
    gw.open("ses_3", "browser");
    gw.mcp("ses_3", initialize(7));
    assert_eq!(gw.recv_mcp("ses_3").await["id"], 7);

    gw.open("ses_l1", "limited");
    gw.open("ses_l2", "limited");
    assert_eq!(gw.recv_close("ses_l2").await, "too_many_sessions");
}

#[tokio::test]
async fn idle_sessions_are_closed() {
    let fake = FakeServer::new();
    let (mut gw, _daemon) = start(vec![fake.entry("fs", SessionMode::PerSession)], |o| {
        o.relay.idle_timeout = Duration::from_millis(300);
    })
    .await;
    gw.open("ses_1", "fs");
    gw.mcp("ses_1", initialize(1));
    assert_eq!(gw.recv_mcp("ses_1").await["id"], 1);
    let pid = fake.pids(1).await[0];
    assert_eq!(gw.recv_close("ses_1").await, "idle");
    assert_dies(pid).await;
}

#[tokio::test]
async fn oversized_gateway_frame_closes_only_that_session() {
    let fake = FakeServer::new();
    let (mut gw, _daemon) = start(vec![fake.entry("fs", SessionMode::PerSession)], |_| {}).await;
    gw.open("ses_1", "fs");
    gw.mcp("ses_1", initialize(1));
    assert_eq!(gw.recv_mcp("ses_1").await["id"], 1);
    let big = Frame::Mcp {
        sid: "ses_1".into(),
        msg: json!({"jsonrpc":"2.0","id":2,"method":"x","params":{"blob":"a".repeat(1 << 20)}}),
    };
    gw.cmd.send(Cmd::SendText(big.to_json().unwrap())).unwrap();
    assert_eq!(gw.recv_close("ses_1").await, "message_too_large");
    // The connection survived.
    gw.open("ses_2", "fs");
    gw.mcp("ses_2", initialize(5));
    assert_eq!(gw.recv_mcp("ses_2").await["id"], 5);
}

#[tokio::test]
async fn dropped_connection_kills_children_and_reconnect_starts_clean() {
    let fake = FakeServer::new();
    let (mut gw, _daemon) =
        start(vec![fake.entry("browser", SessionMode::Exclusive)], |_| {}).await;
    gw.open("ses_1", "browser");
    gw.mcp("ses_1", initialize(1));
    assert_eq!(gw.recv_mcp("ses_1").await["id"], 1);
    let pid = fake.pids(1).await[0];

    gw.cmd.send(Cmd::Drop).unwrap();
    assert_dies(pid).await;

    // The daemon reconnects, advertises again, and the exclusive server is
    // free: nothing of ses_1 survived.
    assert!(matches!(gw.recv().await, Frame::Servers { .. }));
    gw.open("ses_2", "browser");
    gw.mcp("ses_2", initialize(9));
    assert_eq!(gw.recv_mcp("ses_2").await["id"], 9);
}

// ------------------------------------------------------- fake http server

#[derive(Debug, Clone)]
struct HttpRequest {
    method: String,
    headers: Vec<(String, String)>,
    body: Value,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

type Seen = Arc<Mutex<Vec<HttpRequest>>>;

/// A hand-rolled Streamable HTTP MCP endpoint, one request per connection:
/// `initialize` → JSON + `Mcp-Session-Id`; `tools/list` → SSE with a
/// notification and the response; `tools/call` → a JSON-RPC error with
/// HTTP 400; notifications → 202; GET → SSE with one server-initiated
/// message; DELETE → 200.
async fn start_http() -> (String, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Seen = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(handle_http(stream, log.clone()));
        }
    });
    (format!("http://{addr}/mcp"), seen)
}

async fn handle_http(mut stream: TcpStream, seen: Seen) {
    let mut buf = Vec::new();
    let head_end = loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let method = lines.next().unwrap().split(' ').next().unwrap().to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .map_or(0, |(_, v)| v.parse().unwrap());
    while buf.len() < head_end + length {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await.unwrap();
        assert!(n > 0, "request body cut short");
        buf.extend_from_slice(&chunk[..n]);
    }
    let body: Value = serde_json::from_slice(&buf[head_end..]).unwrap_or(Value::Null);
    let req = HttpRequest {
        method,
        headers,
        body,
    };
    seen.lock().unwrap().push(req.clone());

    let id = &req.body["id"];
    let rpc_method = req.body["method"].as_str().unwrap_or("");
    let json_response = |status: &str, extra: &str, body: Value| {
        let body = body.to_string();
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let sse_head =
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n";
    match (req.method.as_str(), rpc_method) {
        ("POST", "initialize") => {
            let body = json!({"jsonrpc":"2.0","id":id,"result":{
                "protocolVersion":"2025-06-18","capabilities":{},
                "serverInfo":{"name":"fake-http","version":"0.0.1"}}});
            let resp = json_response("200 OK", "Mcp-Session-Id: upstream-session-1\r\n", body);
            stream.write_all(resp.as_bytes()).await.unwrap();
        }
        ("POST", "tools/list") => {
            stream.write_all(sse_head.as_bytes()).await.unwrap();
            let progress =
                json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}});
            let first = format!(": keep-alive\n\nevent: message\ndata: {progress}\n\n");
            stream.write_all(first.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
            // The final response arrives later, split across two writes.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let result =
                json!({"jsonrpc":"2.0","id":id,"result":{"tools":[{"name":"echo"}]}}).to_string();
            let (a, b) = result.split_at(10);
            stream
                .write_all(format!("id: 2\r\ndata: {a}").as_bytes())
                .await
                .unwrap();
            stream.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            stream
                .write_all(format!("{b}\r\n\r\n").as_bytes())
                .await
                .unwrap();
        }
        ("POST", "tools/call") => {
            let body =
                json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"bad params"}});
            let resp = json_response("400 Bad Request", "", body);
            stream.write_all(resp.as_bytes()).await.unwrap();
        }
        ("POST", "test/gone") => {
            let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream.write_all(resp.as_bytes()).await.unwrap();
        }
        ("POST", _) => {
            let resp = "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream.write_all(resp.as_bytes()).await.unwrap();
        }
        ("GET", _) => {
            stream.write_all(sse_head.as_bytes()).await.unwrap();
            let ping = json!({"jsonrpc":"2.0","id":"srv-1","method":"ping"});
            stream
                .write_all(format!("data: {ping}\n\n").as_bytes())
                .await
                .unwrap();
            stream.flush().await.unwrap();
            // Hold the stream open like a real server would.
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
        _ => {
            let resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            stream.write_all(resp.as_bytes()).await.unwrap();
        }
    }
    let _ = stream.shutdown().await;
}

#[tokio::test]
async fn http_backend_relays_json_sse_202_and_deletes_on_close() {
    let (url, seen) = start_http().await;
    let entry = ServerEntry::http("gnosys", &url, SessionMode::Shared).unwrap();
    let (mut gw, _daemon) = start(vec![entry], |_| {}).await;

    gw.open("ses_h", "gnosys");
    gw.mcp("ses_h", initialize(1));
    // application/json response.
    let init = gw.recv_mcp("ses_h").await;
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["serverInfo"]["name"], "fake-http");

    // The GET listening stream opens after initialize and relays a
    // server-initiated request.
    let ping = gw.recv_mcp("ses_h").await;
    assert_eq!(ping["id"], "srv-1");
    assert_eq!(ping["method"], "ping");

    // 202 with no body: nothing comes back. The answer to the server's
    // ping goes the same way.
    gw.mcp(
        "ses_h",
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    gw.mcp("ses_h", json!({"jsonrpc":"2.0","id":"srv-1","result":{}}));

    // text/event-stream response: a notification, then the result.
    gw.mcp(
        "ses_h",
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    );
    let progress = gw.recv_mcp("ses_h").await;
    assert_eq!(progress["method"], "notifications/progress");
    let tools = gw.recv_mcp("ses_h").await;
    assert_eq!(tools["id"], 2);
    assert_eq!(tools["result"]["tools"][0]["name"], "echo");

    // A JSON-RPC error with a 4xx status is an answer, not a dead upstream.
    gw.mcp(
        "ses_h",
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}),
    );
    let err = gw.recv_mcp("ses_h").await;
    assert_eq!(err["id"], 3);
    assert_eq!(err["error"]["code"], -32602);

    gw.close("ses_h");
    let delete = eventually("the upstream DELETE", || {
        let seen = seen.lock().unwrap();
        seen.iter().find(|r| r.method == "DELETE").cloned()
    })
    .await;
    assert_eq!(delete.header("mcp-session-id"), Some("upstream-session-1"));

    let seen = seen.lock().unwrap().clone();
    let posts: Vec<&HttpRequest> = seen.iter().filter(|r| r.method == "POST").collect();
    assert_eq!(posts.len(), 5);
    for post in &posts {
        assert_eq!(post.header("content-type"), Some("application/json"));
        assert_eq!(
            post.header("accept"),
            Some("application/json, text/event-stream")
        );
    }
    // initialize goes out bare; everything after carries both headers.
    assert_eq!(posts[0].body, initialize(1));
    assert_eq!(posts[0].header("mcp-session-id"), None);
    for later in seen.iter().filter(|r| r.body["method"] != "initialize") {
        assert_eq!(
            later.header("mcp-session-id"),
            Some("upstream-session-1"),
            "{later:?}"
        );
        assert_eq!(
            later.header("mcp-protocol-version"),
            Some("2025-06-18"),
            "{later:?}"
        );
    }
}

#[tokio::test]
async fn http_upstream_failures_end_the_session() {
    let (url, _seen) = start_http().await;
    // A port nothing listens on.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        format!("http://{}/mcp", l.local_addr().unwrap())
    };
    let entries = vec![
        ServerEntry::http("up", &url, SessionMode::Shared).unwrap(),
        ServerEntry::http("down", &dead, SessionMode::Shared).unwrap(),
    ];
    let (mut gw, _daemon) = start(entries, |_| {}).await;

    gw.open("ses_d", "down");
    gw.mcp("ses_d", initialize(1));
    assert_eq!(gw.recv_close("ses_d").await, "server_exited");

    // 404 without a JSON-RPC body: the upstream session is gone.
    gw.open("ses_u", "up");
    gw.mcp(
        "ses_u",
        json!({"jsonrpc":"2.0","id":1,"method":"test/gone"}),
    );
    assert_eq!(gw.recv_close("ses_u").await, "server_exited");
}

// ------------------------------------------------------ config hot reload

/// A temp config dir the daemon under test follows, polled every 50 ms.
struct LiveConfig {
    dir: tempfile::TempDir,
    cfg: Config,
}

impl LiveConfig {
    async fn start(entries: Vec<ServerEntry>) -> (Gateway, Daemon, LiveConfig) {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = None;
        let (gw, daemon) = start(entries.clone(), |o| {
            let c = Config {
                device_id: o.device_id.clone(),
                handle: "alice".into(),
                device_name: "macbook".into(),
                org_id: None,
                base_url: "https://webmcp.fast".into(),
                relay_url: o.relay_url.clone(),
                hardware_id: "ab".repeat(32),
                servers: entries,
            };
            c.save_to(dir.path()).unwrap();
            o.config_path = Some(Config::path_in(dir.path()));
            o.config_poll_interval = Duration::from_millis(50);
            cfg = Some(c);
        })
        .await;
        let cfg = cfg.unwrap();
        (gw, daemon, LiveConfig { dir, cfg })
    }

    /// What `webmcp attach` / `detach` do: rewrite the file atomically.
    fn rewrite(&mut self, servers: Vec<ServerEntry>) {
        self.cfg.servers = servers;
        self.cfg.save_to(self.dir.path()).unwrap();
    }
}

impl Gateway {
    /// Next frame must be `servers`; returns the advertised aliases.
    async fn recv_servers(&mut self) -> Vec<String> {
        match self.recv().await {
            Frame::Servers { servers } => servers.into_iter().map(|s| s.alias).collect(),
            other => panic!("expected servers, got {other:?}"),
        }
    }

    /// Open `sid` on `server` and return the `serverInfo.name` it answers
    /// `initialize` with.
    async fn init(&mut self, sid: &str, server: &str) -> String {
        self.open(sid, server);
        self.mcp(sid, initialize(1));
        let init = self.recv_mcp(sid).await;
        assert_eq!(init["id"], 1);
        init["result"]["serverInfo"]["name"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// One request/response round on a live session.
    async fn roundtrip(&mut self, sid: &str, id: u64) {
        self.mcp(sid, json!({"jsonrpc":"2.0","id":id,"method":"tools/list"}));
        assert_eq!(self.recv_mcp(sid).await["id"], id);
    }
}

#[tokio::test]
async fn reload_adds_an_alias_without_touching_sessions_and_survives_reconnect() {
    let fake = FakeServer::new();
    let a = fake.entry("a", SessionMode::PerSession);
    let b = fake.entry("b", SessionMode::Shared);
    let (mut gw, _daemon, mut live) = LiveConfig::start(vec![a.clone()]).await;
    assert_eq!(gw.init("ses_1", "a").await, "fake");
    let pid = fake.pids(1).await[0];

    live.rewrite(vec![a, b]);
    assert_eq!(gw.recv_servers().await, ["a", "b"]);
    // The session on `a` never noticed.
    gw.roundtrip("ses_1", 2).await;
    assert!(alive(pid));
    // The new alias is advertised with the shared-stdio rule applied.
    gw.open("ses_b", "b");
    assert_eq!(gw.recv_close("ses_b").await, "unsupported_mode");

    // A reconnect advertises the reloaded set, not the startup one.
    gw.cmd.send(Cmd::Drop).unwrap();
    assert_dies(pid).await;
    let Frame::Servers { servers } = gw.recv().await else {
        panic!("expected servers");
    };
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0].status, ServerStatus::Ready);
    assert_eq!(servers[1].alias, "b");
    assert_eq!(servers[1].status, ServerStatus::Error);
    assert!(servers[1].error.is_some());
}

#[tokio::test]
async fn reload_detach_closes_sessions_and_kills_the_child() {
    let fake = FakeServer::new();
    let a = fake.entry("a", SessionMode::PerSession);
    let b = fake.entry("b", SessionMode::PerSession);
    let (mut gw, _daemon, mut live) = LiveConfig::start(vec![a, b.clone()]).await;
    assert_eq!(gw.init("ses_a", "a").await, "fake");
    let pid_a = fake.pids(1).await[0];
    assert_eq!(gw.init("ses_b", "b").await, "fake");
    let pid_b = fake.pids(2).await[1];

    live.rewrite(vec![b]);
    // The close comes first, then the new set.
    assert_eq!(gw.recv_close("ses_a").await, "detached");
    assert_eq!(gw.recv_servers().await, ["b"]);
    assert_dies(pid_a).await;

    // `b` was not part of the change.
    gw.roundtrip("ses_b", 2).await;
    assert!(alive(pid_b));
    gw.open("ses_a2", "a");
    assert_eq!(gw.recv_close("ses_a2").await, "unknown_server");

    // Detaching the last server advertises an empty set.
    live.rewrite(vec![]);
    assert_eq!(gw.recv_close("ses_b").await, "detached");
    assert!(gw.recv_servers().await.is_empty());
    assert_dies(pid_b).await;
}

#[tokio::test]
async fn reload_with_a_changed_command_reconfigures_only_that_alias() {
    let fake = FakeServer::new();
    let a = fake.entry("a", SessionMode::PerSession);
    let c = fake.entry("c", SessionMode::PerSession);
    let (mut gw, _daemon, mut live) = LiveConfig::start(vec![a, c.clone()]).await;
    assert_eq!(gw.init("ses_a", "a").await, "fake");
    let pid_a = fake.pids(1).await[0];
    assert_eq!(gw.init("ses_c", "c").await, "fake");

    let a2 = fake.named_entry("a", SessionMode::PerSession, Some("fake-v2"));
    live.rewrite(vec![a2, c]);
    assert_eq!(gw.recv_close("ses_a").await, "reconfigured");
    assert_eq!(gw.recv_servers().await, ["a", "c"]);
    assert_dies(pid_a).await;

    // Same alias, new definition; the untouched alias kept its session.
    gw.roundtrip("ses_c", 2).await;
    assert_eq!(gw.init("ses_a2", "a").await, "fake-v2");
}

#[tokio::test]
async fn reload_ignores_an_unreadable_config_until_it_is_valid_again() {
    let fake = FakeServer::new();
    let a = fake.entry("a", SessionMode::PerSession);
    let b = fake.entry("b", SessionMode::PerSession);
    let (mut gw, _daemon, mut live) = LiveConfig::start(vec![a.clone()]).await;
    assert_eq!(gw.init("ses_1", "a").await, "fake");

    // Half a file, as if caught mid-write. Give the 50 ms poll several
    // chances to (wrongly) act on it; too short a wait can only hide a
    // bug, never fail a correct daemon.
    let path = Config::path_in(live.dir.path());
    std::fs::write(&path, "device_id = \"dev_0123").unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    gw.roundtrip("ses_1", 2).await;
    // Valid TOML that is not a config is rejected the same way.
    std::fs::write(&path, "servers = []\n").unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    gw.roundtrip("ses_1", 3).await;
    assert!(gw.frames.try_recv().is_err(), "no frame for a bad config");

    live.rewrite(vec![a, b]);
    assert_eq!(gw.recv_servers().await, ["a", "b"]);
    gw.roundtrip("ses_1", 4).await;
    assert_eq!(gw.init("ses_b", "b").await, "fake");
}

#[tokio::test]
async fn gateway_close_reasons_all_tear_the_session_down_quietly() {
    let fake = FakeServer::new();
    let (mut gw, _daemon) = start(vec![fake.entry("fs", SessionMode::PerSession)], |_| {}).await;
    let reasons = ["restart", "server_disabled", "server_removed"];
    for (i, why) in reasons.into_iter().enumerate() {
        let sid = format!("ses_{i}");
        assert_eq!(gw.init(&sid, "fs").await, "fake");
        let pid = fake.pids(i + 1).await[i];
        gw.send(Frame::SessionClose {
            sid: sid.clone(),
            reason: Some(why.into()),
        });
        assert_dies(pid).await;
    }
    // No replies to those closes, and the connection is still up.
    assert_eq!(gw.init("ses_after", "fs").await, "fake");
}

#[tokio::test]
async fn gateway_detach_removes_the_alias_from_the_config_and_nothing_else() {
    let fake = FakeServer::new();
    let a = fake.entry("a", SessionMode::PerSession);
    let b = fake.entry("b", SessionMode::PerSession);
    let (mut gw, _daemon, live) = LiveConfig::start(vec![a, b]).await;
    assert_eq!(gw.init("ses_a", "a").await, "fake");
    let pid_a = fake.pids(1).await[0];

    // The owner clicked Remove on the dashboard.
    gw.send(Frame::Detach { alias: "a".into() });
    assert_eq!(gw.recv_close("ses_a").await, "detached");
    assert_eq!(gw.recv_servers().await, ["b"]);
    assert_dies(pid_a).await;
    let saved = Config::load_path(&Config::path_in(live.dir.path())).unwrap();
    assert_eq!(saved.servers.len(), 1);
    assert_eq!(saved.servers[0].alias, "b");

    // An alias that is already gone is not an error and changes nothing.
    gw.send(Frame::Detach {
        alias: "nope".into(),
    });
    gw.open("ses_b", "b");
    gw.mcp("ses_b", initialize(1));
    assert_eq!(gw.recv_mcp("ses_b").await["id"], 1);
}
