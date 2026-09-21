// The upgrade callback signature is fixed by tungstenite; its Err type is large.
#![allow(clippy::result_large_err)]

//! Drive the library connect loop against an in-process mock gateway that
//! speaks protocol §2 (handshake + ping/pong) over tokio-tungstenite.

use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::Message;
use webmcp_daemon::connect::{self, ConnectError, ConnectOptions};
use webmcp_daemon::keys;
use webmcp_daemon::proto::{
    connect_sign_message, Frame, ServerInfo, ServerStatus, SessionMode, Transport,
    CLOSE_UNAUTHORIZED, PING, PONG,
};

const DEVICE_ID: &str = "dev_0123456789abcdef";

/// What the mock observed, for assertions.
#[derive(Debug)]
enum Event {
    Upgrade {
        device_id: Option<String>,
        user_agent: Option<String>,
    },
    Hello(Frame),
    AuthOk,
    AuthBad,
    Servers(Vec<ServerInfo>),
    Ping,
    Closed,
}

struct Gateway {
    url: String,
    events: mpsc::UnboundedReceiver<Event>,
}

/// Start a mock gateway that accepts one connection at a time (looping),
/// verifying signatures against `trusted`. `reject_upgrade` makes it answer
/// the HTTP upgrade with 404, like an unknown device.
async fn start_gateway(trusted: VerifyingKey, reject_upgrade: bool) -> Gateway {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let tx = tx.clone();
            tokio::spawn(serve(stream, trusted, reject_upgrade, tx));
        }
    });
    Gateway {
        url: format!("ws://{addr}/connect"),
        events: rx,
    }
}

async fn serve(
    stream: tokio::net::TcpStream,
    trusted: VerifyingKey,
    reject_upgrade: bool,
    tx: mpsc::UnboundedSender<Event>,
) {
    let tx2 = tx.clone();
    let callback = move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
        let device_id = req.uri().query().and_then(|q| {
            url::form_urlencoded::parse(q.as_bytes())
                .find(|(k, _)| k == "device_id")
                .map(|(_, v)| v.into_owned())
        });
        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let _ = tx2.send(Event::Upgrade {
            device_id: device_id.clone(),
            user_agent,
        });
        if reject_upgrade || device_id.as_deref() != Some(DEVICE_ID) {
            let mut err = ErrorResponse::new(Some("unknown device".into()));
            *err.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::NOT_FOUND;
            return Err(err);
        }
        Ok(resp)
    };
    let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
        return;
    };

    let recv_frame = |m: Option<Result<Message, _>>| -> Option<Frame> {
        match m {
            Some(Ok(Message::Text(t))) => Frame::from_json(t.as_str()).ok(),
            _ => None,
        }
    };

    // hello
    let hello = recv_frame(ws.next().await);
    let Some(Frame::Hello {
        v, ref device_id, ..
    }) = hello
    else {
        let _ = ws
            .close(Some(CloseFrame {
                code: CloseCode::Library(4400),
                reason: "".into(),
            }))
            .await;
        return;
    };
    assert_eq!(v, 1);
    assert_eq!(device_id, DEVICE_ID);
    let _ = tx.send(Event::Hello(hello.clone().unwrap()));

    // challenge
    let nonce_bytes: [u8; 32] = rand::random();
    let nonce = B64.encode(nonce_bytes);
    ws.send(Message::text(
        Frame::Challenge {
            nonce: nonce.clone(),
        }
        .to_json()
        .unwrap(),
    ))
    .await
    .unwrap();

    // auth
    let Some(Frame::Auth { signature }) = recv_frame(ws.next().await) else {
        let _ = ws
            .close(Some(CloseFrame {
                code: CloseCode::Library(4400),
                reason: "".into(),
            }))
            .await;
        return;
    };
    let ok = B64
        .decode(&signature)
        .ok()
        .and_then(|raw| Signature::from_slice(&raw).ok())
        .map(|sig| {
            trusted
                .verify(&connect_sign_message(DEVICE_ID, &nonce), &sig)
                .is_ok()
        })
        .unwrap_or(false);
    if !ok {
        let _ = tx.send(Event::AuthBad);
        let _ = ws
            .send(Message::text(
                Frame::Error {
                    code: "unauthorized".into(),
                    message: None,
                }
                .to_json()
                .unwrap(),
            ))
            .await;
        let _ = ws
            .close(Some(CloseFrame {
                code: CloseCode::Library(CLOSE_UNAUTHORIZED),
                reason: "unauthorized".into(),
            }))
            .await;
        // Drain so the close handshake completes.
        while let Some(Ok(_)) = ws.next().await {}
        let _ = tx.send(Event::Closed);
        return;
    }
    let _ = tx.send(Event::AuthOk);
    ws.send(Message::text(
        Frame::Welcome {
            handle: "alice".into(),
            device: "macbook".into(),
            server_time: "2026-09-19T21:00:00Z".into(),
        }
        .to_json()
        .unwrap(),
    ))
    .await
    .unwrap();

    // Throw in a frame the daemon does not know; it must be ignored.
    ws.send(Message::text(r#"{"t":"gateway_notice","text":"hi"}"#))
        .await
        .unwrap();

    while let Some(Ok(msg)) = ws.next().await {
        match msg {
            Message::Text(t) if t.as_str() == PING => {
                let _ = tx.send(Event::Ping);
                ws.send(Message::text(PONG)).await.unwrap();
            }
            Message::Text(t) => {
                if let Ok(Frame::Servers { servers }) = Frame::from_json(t.as_str()) {
                    let _ = tx.send(Event::Servers(servers));
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    let _ = tx.send(Event::Closed);
}

fn fast_opts(url: &str, key: ed25519_dalek::SigningKey) -> ConnectOptions {
    let mut o = ConnectOptions::new(url.to_string(), DEVICE_ID.to_string(), key);
    o.once = true;
    o.ping_interval = Duration::from_millis(50);
    o.handshake_timeout = Duration::from_secs(5);
    o.backoff_min = Duration::from_millis(10);
    o.backoff_max = Duration::from_millis(50);
    o
}

async fn drain(gw: &mut Gateway) -> Vec<Event> {
    let mut out = Vec::new();
    while let Ok(Some(e)) = tokio::time::timeout(Duration::from_millis(300), gw.events.recv()).await
    {
        out.push(e);
    }
    out
}

#[tokio::test]
async fn connect_once_succeeds_with_correct_key() {
    let key = keys::generate();
    let mut gw = start_gateway(key.verifying_key(), false).await;
    let mut opts = fast_opts(&gw.url, key);
    opts.servers = vec![ServerInfo {
        alias: "gnosys".into(),
        transport: Transport::Stdio,
        mode: SessionMode::PerSession,
        status: ServerStatus::Ready,
        error: None,
    }];

    let welcome = tokio::time::timeout(Duration::from_secs(10), connect::run(&opts))
        .await
        .expect("did not hang")
        .expect("connect --once succeeds");
    assert_eq!(welcome.handle, "alice");
    assert_eq!(welcome.device, "macbook");

    let events = drain(&mut gw).await;
    let mut saw = (false, false, false, false, false);
    for e in &events {
        match e {
            Event::Upgrade {
                device_id,
                user_agent,
            } => {
                assert_eq!(device_id.as_deref(), Some(DEVICE_ID));
                assert!(user_agent
                    .as_deref()
                    .unwrap_or("")
                    .starts_with("webmcp-daemon/0.1.0 ("));
                saw.0 = true;
            }
            Event::Hello(Frame::Hello {
                daemon_version,
                platform,
                ..
            }) => {
                assert_eq!(daemon_version, "0.1.0");
                assert!(platform.contains('-'));
                saw.1 = true;
            }
            Event::AuthOk => saw.2 = true,
            Event::Servers(s) => {
                assert_eq!(s, &opts.servers);
                saw.3 = true;
            }
            Event::Ping => saw.4 = true,
            Event::AuthBad => panic!("auth rejected"),
            _ => {}
        }
    }
    assert_eq!(saw, (true, true, true, true, true), "events: {events:?}");
}

#[tokio::test]
async fn connect_is_rejected_with_wrong_key() {
    let trusted = keys::generate();
    let wrong = keys::generate();
    let mut gw = start_gateway(trusted.verifying_key(), false).await;
    let opts = fast_opts(&gw.url, wrong);

    let err = tokio::time::timeout(Duration::from_secs(10), connect::run(&opts))
        .await
        .expect("did not hang")
        .expect_err("wrong key must be rejected");
    assert!(matches!(err, ConnectError::Unauthorized), "{err:?}");
    assert!(err.is_fatal());

    let events = drain(&mut gw).await;
    assert!(
        events.iter().any(|e| matches!(e, Event::AuthBad)),
        "{events:?}"
    );
    assert!(!events
        .iter()
        .any(|e| matches!(e, Event::AuthOk | Event::Ping)));
    // Fatal: exactly one upgrade attempt, no reconnect.
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, Event::Upgrade { .. }))
            .count(),
        1
    );
}

#[tokio::test]
async fn unknown_device_404_is_fatal() {
    let key = keys::generate();
    let gw = start_gateway(key.verifying_key(), true).await;
    let opts = fast_opts(&gw.url, key);
    let err = tokio::time::timeout(Duration::from_secs(10), connect::run(&opts))
        .await
        .expect("did not hang")
        .expect_err("404 must be fatal");
    assert!(matches!(err, ConnectError::UnknownDevice), "{err:?}");
}

#[tokio::test]
async fn reconnects_after_a_dropped_connection() {
    // First attempt hits a listener that closes immediately; the loop must
    // back off and retry rather than give up. We simulate by pointing at a
    // port that refuses, then swapping in a real gateway is not possible on
    // the same port, so instead: a gateway whose first connection is cut.
    let key = keys::generate();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let trusted = key.verifying_key();
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        // Connection 1: accept TCP and drop it (no upgrade).
        let (s, _) = listener.accept().await.unwrap();
        drop(s);
        // Connection 2: a proper gateway.
        let (s, _) = listener.accept().await.unwrap();
        serve(s, trusted, false, tx).await;
    });
    let opts = fast_opts(&format!("ws://{addr}/connect"), key);
    let welcome = tokio::time::timeout(Duration::from_secs(10), connect::run(&opts))
        .await
        .expect("did not hang")
        .expect("second attempt succeeds");
    assert_eq!(welcome.handle, "alice");
    let mut saw_ping = false;
    while let Ok(Some(e)) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
        if matches!(e, Event::Ping) {
            saw_ping = true;
        }
    }
    assert!(saw_ping);
}
