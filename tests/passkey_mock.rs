//! `webmcp passkey` against an in-process mock gateway (a bare tokio
//! listener speaking just enough HTTP/1.1): the request the daemon sends,
//! the signature over the documented string, and what the CLI prints for a
//! link and for a refusal.

use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use webmcp_daemon::keys;
use webmcp_daemon::output::{self, ErrorReport, PasskeyLinkReport};
use webmcp_daemon::passkey::{self, PasskeyError, PasskeyLink};

const DEVICE_ID: &str = "dev_0123456789abcdef";
const TS: u64 = 1_790_000_000;

/// One request as the mock saw it.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    user_agent: String,
    content_type: String,
    host: String,
    signature_input: String,
    signature: String,
    content_digest: String,
    body: Value,
}

/// A gateway that answers every request with `status` and `body` (sent
/// as-is when it is a string, as JSON otherwise).
async fn gateway(status: u16, body: Value) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let base = base_url.clone();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let Some(req) = read_request(&mut stream).await else {
                continue;
            };
            log.lock().unwrap().push(req);
            let (text, kind) = match &body {
                Value::String(s) => (s.clone(), "text/plain"),
                other => (other.to_string(), "application/json"),
            };
            // Links the real gateway returns are on its own origin.
            let text = text.replace("{base}", &base);
            let head = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: {kind}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                text.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(text.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    (base_url, seen)
}

async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<Seen> {
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
    let mut request_line = head.split_whitespace();
    Some(Seen {
        method: request_line.next()?.to_string(),
        path: request_line.next()?.to_string(),
        user_agent: header("user-agent").unwrap_or_default(),
        content_type: header("content-type").unwrap_or_default(),
        host: header("host").unwrap_or_default(),
        signature_input: header("signature-input").unwrap_or_default(),
        signature: header("signature").unwrap_or_default(),
        content_digest: header("content-digest").unwrap_or_default(),
        body: serde_json::from_slice(&buf[header_end..header_end + length]).ok()?,
    })
}

#[tokio::test]
async fn a_signed_request_gets_a_link() {
    let key = keys::generate();
    let (base, seen) = gateway(
        201,
        json!({ "url": "{base}/app/security?link=pkl_0123456789abcdef", "expires_in": 600 }),
    )
    .await;
    let url = format!("{base}/app/security?link=pkl_0123456789abcdef");
    let url = url.as_str();
    let link = passkey::request_link(&base, DEVICE_ID, &key, TS)
        .await
        .unwrap();
    assert_eq!(
        link,
        PasskeyLink {
            url: url.into(),
            expires_in: 600
        }
    );

    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let req = &seen[0];
    assert_eq!(
        (req.method.as_str(), req.path.as_str()),
        ("POST", "/api/v1/device/passkey-link")
    );
    assert!(req.user_agent.starts_with("webmcp-daemon/"), "{req:?}");
    assert_eq!(req.content_type, "application/json");
    // An empty JSON body, signed with RFC 9421 over the device key.
    assert_eq!(req.body, json!({}));
    assert_eq!(
        req.content_digest,
        "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:"
    );
    let params = req.signature_input.strip_prefix("webmcp=").unwrap();
    assert!(params.starts_with(
        "(\"@method\" \"@authority\" \"@path\" \"@query\" \"content-digest\");created=1790000000;"
    ));
    assert!(
        params.contains(&format!("keyid=\"{DEVICE_ID}\""))
            && params.contains("tag=\"webmcp-device\"")
    );
    let base = format!(
        "\"@method\": POST\n\"@authority\": {}\n\"@path\": /api/v1/device/passkey-link\n\"@query\": ?\n\"content-digest\": {}\n\"@signature-params\": {params}",
        req.host, req.content_digest
    );
    let b64 = req
        .signature
        .strip_prefix("webmcp=:")
        .unwrap()
        .trim_end_matches(':');
    let sig = Signature::from_slice(&B64.decode(b64).unwrap()).unwrap();
    key.verifying_key()
        .verify(base.as_bytes(), &sig)
        .expect("the signature covers the RFC 9421 signature base");
    assert!(keys::generate()
        .verifying_key()
        .verify(base.as_bytes(), &sig)
        .is_err());

    // What `webmcp passkey` prints, with and without --json.
    assert_eq!(
        output::line(&PasskeyLinkReport::new(&link)),
        format!(r#"{{"event":"passkey_link","url":"{url}","expires_in":600}}"#)
    );
    assert_eq!(
        passkey::instructions("alice", "https://webmcp.fast", &link),
        "Open this link in the browser where you are signed in to alice.webmcp.fast, within 10 minutes, and add a passkey."
    );
}

#[tokio::test]
async fn a_bad_signature_is_reported_with_the_gateways_code_and_message() {
    let (base, _seen) = gateway(
        401,
        json!({ "error": "bad_signature", "message": "signature does not verify" }),
    )
    .await;
    let err = passkey::request_link(&base, DEVICE_ID, &keys::generate(), TS)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, PasskeyError::Refused { status: 401, .. }),
        "{err:?}"
    );
    assert_eq!(err.code(), "bad_signature");
    let message = "passkey link refused: bad_signature (signature does not verify). The gateway did not accept this device's key; if this machine was paired again elsewhere, run `webmcp up --force`.";
    assert_eq!(err.to_string(), message);
    // Under --json the CLI prints the error object with the gateway's code.
    assert_eq!(
        output::line(&ErrorReport::new(err.code(), &err.to_string())),
        format!(r#"{{"event":"error","code":"bad_signature","message":"{message}"}}"#)
    );
}

#[tokio::test]
async fn other_failures_keep_their_codes() {
    let key = keys::generate();
    let code = |err: PasskeyError| err.code().to_string();

    let (base, _) = gateway(401, json!({ "error": "clock_skew" })).await;
    let err = passkey::request_link(&base, DEVICE_ID, &key, TS)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "passkey link refused: clock_skew. This machine's clock is more than 5 minutes off; correct it and retry."
    );

    // An edge rate limiter without a JSON body still reads as rate_limited.
    let (base, _) = gateway(429, json!("slow down")).await;
    let err = passkey::request_link(&base, DEVICE_ID, &key, TS)
        .await
        .unwrap_err();
    assert_eq!(code(err), "rate_limited");

    let (base, _) = gateway(502, json!("<html>bad gateway</html>")).await;
    let err = passkey::request_link(&base, DEVICE_ID, &key, TS)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("<html>bad gateway</html>"),
        "{err}"
    );
    assert_eq!(code(err), "unexpected_response");

    // A success that is not a web link is never printed or opened.
    let (base, _) = gateway(
        201,
        json!({ "url": "file:///etc/passwd", "expires_in": 600 }),
    )
    .await;
    let err = passkey::request_link(&base, DEVICE_ID, &key, TS)
        .await
        .unwrap_err();
    assert_eq!(code(err), "unexpected_response");

    // Nothing listening.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let err = passkey::request_link(&dead, DEVICE_ID, &key, TS)
        .await
        .unwrap_err();
    assert_eq!(code(err), "network");
}
