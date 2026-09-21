//! Drive the §1a device authorization flow against an in-process mock
//! gateway: a bare tokio listener speaking just enough HTTP/1.1. Protocol
//! seconds are shrunk to a millisecond so whole flows finish instantly.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use webmcp_daemon::config::Config;
use webmcp_daemon::device_auth::{self, DeviceAuthError, PollTiming, StartRequest, StartResponse};
use webmcp_daemon::{keys, pair};

const DEVICE_CODE: &str = "dc_0123456789abcdefghijklmnopqrstuvwxyzABCDE";
const FAST: PollTiming = PollTiming {
    second: Duration::from_millis(1),
};

/// One request as the mock saw it.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    user_agent: String,
    body: Value,
    at: Instant,
}

struct Gateway {
    base_url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Gateway {
    fn polls(&self) -> Vec<Seen> {
        let seen = self.seen.lock().unwrap();
        seen.iter()
            .filter(|s| s.path == "/api/v1/device/poll")
            .cloned()
            .collect()
    }
}

fn start_body(base_url: &str, expires_in: u64, interval: u64) -> Value {
    json!({
        "device_code": DEVICE_CODE,
        "user_code": "ABCD-EFGH",
        "verification_uri": format!("{base_url}/activate"),
        "verification_uri_complete": format!("{base_url}/activate?code=ABCD-EFGH"),
        "expires_in": expires_in,
        "interval": interval
    })
}

fn paired_body(base_url: &str) -> Value {
    json!({
        "device_id": "dev_0123456789abcdef",
        "handle": "alice",
        "org_id": "org_1",
        "relay_url": "wss://webmcp.fast/connect",
        "base_url": base_url
    })
}

/// Start a mock that answers `device/start` with `start` and each
/// `device/poll` with the next scripted `(status, body)`; when the script
/// runs out it keeps answering `authorization_pending`.
async fn gateway(start: (u16, Value), polls: Vec<(u16, Value)>) -> Gateway {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let script = Arc::new(Mutex::new(VecDeque::from(polls)));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let (log, script, start) = (log.clone(), script.clone(), start.clone());
            tokio::spawn(async move {
                let Some((path, user_agent, body)) = read_request(&mut stream).await else {
                    return;
                };
                log.lock().unwrap().push(Seen {
                    path: path.clone(),
                    user_agent,
                    body,
                    at: Instant::now(),
                });
                let (status, body) = match path.as_str() {
                    "/api/v1/device/start" => start,
                    "/api/v1/device/poll" => script
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or((400, json!({"error": "authorization_pending"}))),
                    _ => (404, json!({"error": "not_found"})),
                };
                let body = body.to_string();
                let head = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Gateway { base_url, seen }
}

/// Read one request: `(path, user-agent, JSON body)`.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<(String, String, Value)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let header = |name: &str| {
        head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    };
    let length: usize = header("content-length")?.parse().ok()?;
    while buf.len() < header_end + length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let path = head.split_whitespace().nth(1)?.to_string();
    let body = serde_json::from_slice(&buf[header_end..header_end + length]).ok()?;
    Some((path, header("user-agent").unwrap_or_default(), body))
}

fn request(key: &ed25519_dalek::SigningKey) -> StartRequest {
    StartRequest {
        device_name: "studio".into(),
        public_key: keys::public_key_b64(key),
        hardware_id: "ab".repeat(32),
        daemon_version: "0.1.0".into(),
        platform: "macos-aarch64".into(),
    }
}

async fn started(gw: &Gateway, key: &ed25519_dalek::SigningKey) -> StartResponse {
    device_auth::start(&gw.base_url, &request(key))
        .await
        .unwrap()
}

fn err(error: &str) -> (u16, Value) {
    (400, json!({ "error": error }))
}

#[tokio::test]
async fn pending_then_slow_down_then_approved_persists_config_and_key() {
    let base = "https://webmcp.fast".to_string();
    let gw = gateway(
        (200, start_body(&base, 900, 3)),
        vec![
            err("authorization_pending"),
            err("slow_down"),
            err("authorization_pending"),
            (200, paired_body(&base)),
        ],
    )
    .await;

    let key = keys::generate();
    let start = started(&gw, &key).await;
    assert_eq!(start.user_code, "ABCD-EFGH");
    assert_eq!(start.device_code, DEVICE_CODE);
    assert_eq!((start.expires_in, start.interval), (900, 3));
    assert!(start.verification_uri_complete.ends_with("?code=ABCD-EFGH"));

    let resp = device_auth::wait(&gw.base_url, &start, "studio", FAST)
        .await
        .unwrap();
    assert_eq!(resp.handle, "alice");

    // What went over the wire.
    let seen = gw.seen.lock().unwrap().clone();
    assert_eq!(seen[0].path, "/api/v1/device/start");
    assert!(seen[0].user_agent.starts_with("webmcp-daemon/"));
    assert_eq!(seen[0].body["device_name"], "studio");
    assert_eq!(seen[0].body["public_key"], keys::public_key_b64(&key));
    assert_eq!(seen[0].body["hardware_id"], "ab".repeat(32));
    let polls = gw.polls();
    assert_eq!(polls.len(), 4);
    assert!(polls
        .iter()
        .all(|p| p.body == json!({ "device_code": DEVICE_CODE })));
    // interval 3 → polls at least 3 "seconds" apart; after slow_down, 8.
    let gap = |i: usize| polls[i].at.duration_since(polls[i - 1].at);
    assert!(gap(1) >= Duration::from_millis(3), "{:?}", gap(1));
    assert!(gap(2) >= Duration::from_millis(8), "{:?}", gap(2));
    assert!(gap(3) >= Duration::from_millis(8), "{:?}", gap(3));

    // Persisted exactly as `login` does: key (0600) and config, all fields.
    let dir = tempfile::tempdir().unwrap();
    let cfg = pair::persist(
        dir.path(),
        &key,
        resp,
        "studio".into(),
        "ab".repeat(32),
        vec![],
    )
    .unwrap();
    let back = Config::load_from(dir.path()).unwrap();
    assert_eq!(back, cfg);
    assert_eq!(back.device_id, "dev_0123456789abcdef");
    assert_eq!(back.handle, "alice");
    assert_eq!(back.device_name, "studio");
    assert_eq!(back.org_id.as_deref(), Some("org_1"));
    assert_eq!(back.relay_url, "wss://webmcp.fast/connect");
    assert_eq!(back.base_url, base);
    assert_eq!(
        keys::load(dir.path()).unwrap().to_bytes(),
        key.to_bytes(),
        "the key generated before `start` is the one persisted"
    );
}

#[tokio::test]
async fn a_device_name_chosen_on_the_approval_page_wins() {
    let mut body = paired_body("https://webmcp.fast");
    body["device_name"] = json!("renamed");
    let gw = gateway(
        (200, start_body("https://webmcp.fast", 900, 1)),
        vec![(200, body)],
    )
    .await;
    let key = keys::generate();
    let start = started(&gw, &key).await;
    let resp = device_auth::wait(&gw.base_url, &start, "studio", FAST)
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cfg = pair::persist(dir.path(), &key, resp, "studio".into(), "00".into(), vec![]).unwrap();
    assert_eq!(cfg.device_name, "renamed");
}

#[tokio::test]
async fn denied_stops_with_exit_code_2() {
    let gw = gateway(
        (200, start_body("https://webmcp.fast", 900, 1)),
        vec![err("authorization_pending"), err("access_denied")],
    )
    .await;
    let start = started(&gw, &keys::generate()).await;
    let e = device_auth::wait(&gw.base_url, &start, "studio", FAST)
        .await
        .unwrap_err();
    assert!(matches!(e, DeviceAuthError::AccessDenied), "{e:?}");
    assert_eq!((e.exit_code(), e.code()), (2, "access_denied"));
    assert_eq!(gw.polls().len(), 2, "no poll after the verdict");
}

#[tokio::test]
async fn expired_token_stops_with_exit_code_3() {
    let gw = gateway(
        (200, start_body("https://webmcp.fast", 900, 1)),
        vec![err("expired_token")],
    )
    .await;
    let start = started(&gw, &keys::generate()).await;
    let e = device_auth::wait(&gw.base_url, &start, "studio", FAST)
        .await
        .unwrap_err();
    assert!(matches!(e, DeviceAuthError::Expired), "{e:?}");
    assert_eq!((e.exit_code(), e.code()), (3, "expired_token"));
}

#[tokio::test]
async fn expires_locally_when_the_gateway_only_ever_says_pending() {
    // 20 "seconds" to live, polled every 5: gives up by itself.
    let gw = gateway((200, start_body("https://webmcp.fast", 20, 5)), vec![]).await;
    let start = started(&gw, &keys::generate()).await;
    let e = device_auth::wait(&gw.base_url, &start, "studio", FAST)
        .await
        .unwrap_err();
    assert!(matches!(e, DeviceAuthError::Expired), "{e:?}");
    let polls = gw.polls().len();
    assert!((1..=4).contains(&polls), "{polls} polls");
}

#[tokio::test]
async fn conflicts_decided_at_approval_time_stop_the_flow() {
    for (error, code) in [
        ("device_limit", "device_limit"),
        ("device_name_taken", "device_name_taken"),
        ("hardware_already_paired", "hardware_already_paired"),
    ] {
        let gw = gateway(
            (200, start_body("https://webmcp.fast", 900, 1)),
            vec![(409, json!({ "error": error }))],
        )
        .await;
        let start = started(&gw, &keys::generate()).await;
        let e = device_auth::wait(&gw.base_url, &start, "studio", FAST)
            .await
            .unwrap_err();
        assert_eq!((e.code(), e.exit_code()), (code, 1), "{e:?}");
        if error == "device_limit" {
            assert!(matches!(e, DeviceAuthError::DeviceLimit));
        }
        if error == "device_name_taken" {
            assert!(e.to_string().contains("`studio`"), "{e}");
        }
    }
}

#[tokio::test]
async fn a_5xx_while_polling_is_retried() {
    let gw = gateway(
        (200, start_body("https://webmcp.fast", 900, 1)),
        vec![
            (502, json!({"error": "bad_gateway"})),
            (200, paired_body("https://webmcp.fast")),
        ],
    )
    .await;
    let start = started(&gw, &keys::generate()).await;
    let resp = device_auth::wait(&gw.base_url, &start, "studio", FAST)
        .await
        .unwrap();
    assert_eq!(resp.device_id, "dev_0123456789abcdef");
}

#[tokio::test]
async fn start_errors_map() {
    let gw = gateway(
        (
            400,
            json!({"error": "invalid_request", "message": "bad device name"}),
        ),
        vec![],
    )
    .await;
    let e = device_auth::start(&gw.base_url, &request(&keys::generate()))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, DeviceAuthError::InvalidRequest(m) if m == "bad device name"),
        "{e:?}"
    );

    let gw = gateway((429, json!({"error": "rate_limited"})), vec![]).await;
    let e = device_auth::start(&gw.base_url, &request(&keys::generate()))
        .await
        .unwrap_err();
    assert!(matches!(e, DeviceAuthError::RateLimited), "{e:?}");
}
