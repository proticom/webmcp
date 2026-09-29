//! `webmcp passkey`: a one-time link that lets a signed-in browser add a
//! passkey to an account without an existing one (protocol §1b). The gateway
//! only hands it to a paired device, which proves it holds its key by signing
//! the current time. So knowing the owner's email is not enough to enroll a
//! passkey first.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::{keys, platform};

/// Prefix of the message signed for a passkey link.
pub const SIGN_PREFIX: &str = "webmcp-passkey-link-v1\n";

/// The exact bytes signed: `"webmcp-passkey-link-v1\n" + device_id + "\n" + ts`,
/// with `ts` in decimal as sent.
pub fn sign_message(device_id: &str, ts: u64) -> Vec<u8> {
    format!("{SIGN_PREFIX}{device_id}\n{ts}").into_bytes()
}

/// Request body for `POST /api/v1/device/passkey-link`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LinkRequest {
    pub device_id: String,
    /// Unix seconds on this machine's clock.
    pub ts: u64,
    /// Standard base64 of the 64-byte Ed25519 signature.
    pub signature: String,
}

impl LinkRequest {
    pub fn signed(device_id: &str, key: &SigningKey, ts: u64) -> Self {
        LinkRequest {
            device_id: device_id.to_string(),
            ts,
            signature: keys::sign_b64(key, &sign_message(device_id, ts)),
        }
    }
}

/// The success body: a link to open, good for `expires_in` seconds.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PasskeyLink {
    pub url: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PasskeyError {
    /// The gateway said no; `error` is its code (`invalid_request`,
    /// `unknown_device`, `bad_signature`, `clock_skew`, `rate_limited`).
    #[error("passkey link refused: {error}{}.{}", detail(.message), hint(.error))]
    Refused {
        status: u16,
        error: String,
        message: Option<String>,
    },
    #[error("unexpected response {status} from {url}: {body}")]
    Unexpected {
        status: u16,
        url: String,
        body: String,
    },
    #[error("request to {url} failed")]
    Transport {
        url: String,
        #[source]
        source: reqwest::Error,
    },
}

impl PasskeyError {
    /// Stable machine-readable name: the gateway's own code where it sent one.
    pub fn code(&self) -> &str {
        match self {
            PasskeyError::Refused { error, .. } => error,
            PasskeyError::Unexpected { .. } => "unexpected_response",
            PasskeyError::Transport { .. } => "network",
        }
    }
}

fn detail(message: &Option<String>) -> String {
    match message.as_deref().map(|m| m.trim().trim_end_matches('.')) {
        Some(m) if !m.is_empty() => format!(" ({m})"),
        _ => String::new(),
    }
}

fn hint(error: &str) -> &'static str {
    match error {
        "unknown_device" => {
            " The gateway does not know this device; `webmcp up --force` pairs it again."
        }
        "bad_signature" => {
            " The gateway did not accept this device's key; if this machine was paired again elsewhere, run `webmcp up --force`."
        }
        "clock_skew" => " This machine's clock is more than 5 minutes off; correct it and retry.",
        "rate_limited" => " Too many links were asked for; wait a few minutes and retry.",
        _ => "",
    }
}

pub fn link_url(base_url: &str) -> String {
    format!(
        "{}/api/v1/device/passkey-link",
        base_url.trim_end_matches('/')
    )
}

/// Ask the gateway at `base_url` for a passkey link, signed with the device
/// key as of `ts` (Unix seconds).
/// `link` is on `base_url`'s scheme and host.
fn same_site(base_url: &str, link: &str) -> bool {
    match (url::Url::parse(base_url), url::Url::parse(link)) {
        (Ok(b), Ok(l)) => {
            matches!(l.scheme(), "https" | "http")
                && l.scheme() == b.scheme()
                && l.host_str().is_some()
                && l.host_str().map(str::to_ascii_lowercase)
                    == b.host_str().map(str::to_ascii_lowercase)
                && l.port_or_known_default() == b.port_or_known_default()
        }
        _ => false,
    }
}

pub async fn request_link(
    base_url: &str,
    device_id: &str,
    key: &SigningKey,
    ts: u64,
) -> Result<PasskeyLink, PasskeyError> {
    let url = link_url(base_url);
    let transport = |source| PasskeyError::Transport {
        url: url.clone(),
        source,
    };
    let client = reqwest::Client::builder()
        .user_agent(platform::user_agent())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(transport)?;
    let resp = client
        .post(&url)
        .json(&LinkRequest::signed(device_id, key, ts))
        .send()
        .await
        .map_err(transport)?;
    let status = resp.status().as_u16();
    let body = resp.text().await.map_err(transport)?;
    let unexpected = |body: String| PasskeyError::Unexpected {
        status,
        url: url.clone(),
        body: if body.is_empty() {
            "<empty body>".into()
        } else {
            body
        },
    };
    if (200..300).contains(&status) {
        let link: PasskeyLink = serde_json::from_str(&body)
            .map_err(|e| unexpected(format!("could not parse body ({e}): {body}")))?;
        // It is printed and handed to the browser opener: only a page on the
        // site this machine is paired with, never a file or app scheme.
        return if same_site(base_url, &link.url) {
            Ok(link)
        } else {
            Err(unexpected(format!(
                "not a link to {base_url}: {}",
                link.url
            )))
        };
    }
    match serde_json::from_str::<ErrorBody>(&body) {
        Ok(err) if !err.error.is_empty() => Err(PasskeyError::Refused {
            status,
            error: err.error,
            message: err.message,
        }),
        _ if status == 429 => Err(PasskeyError::Refused {
            status,
            error: "rate_limited".into(),
            message: None,
        }),
        _ => Err(unexpected(body)),
    }
}

/// The line `webmcp passkey` prints above the link. The site is where the
/// owner signs in: `<handle>.<host of base_url>`.
pub fn instructions(handle: &str, base_url: &str, link: &PasskeyLink) -> String {
    let site = url::Url::parse(base_url)
        .ok()
        .and_then(|u| {
            let host = u.host_str()?.to_string();
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            Some(format!("{handle}.{host}{port}"))
        })
        .unwrap_or_else(|| format!("{handle}.webmcp.fast"));
    let minutes = link.expires_in.div_ceil(60).max(1);
    let unit = if minutes == 1 { "minute" } else { "minutes" };
    format!(
        "Open this link in the browser where you are signed in to {site}, within {minutes} {unit}, and add a passkey."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_must_point_at_the_paired_site() {
        assert!(same_site(
            "https://webmcp.fast",
            "https://webmcp.fast/app/security?link=x"
        ));
        assert!(same_site(
            "http://localhost:8788",
            "http://localhost:8788/app/security"
        ));
        assert!(!same_site(
            "https://webmcp.fast",
            "https://evil.example/app/security"
        ));
        assert!(!same_site(
            "https://webmcp.fast",
            "http://webmcp.fast/app/security"
        ));
        assert!(!same_site(
            "https://webmcp.fast",
            "https://webmcp.fast.evil.example/"
        ));
        assert!(!same_site("https://webmcp.fast", "file:///etc/passwd"));
    }

    #[test]
    fn signed_string_layout() {
        assert_eq!(
            sign_message("dev_abc", 1_790_000_000),
            b"webmcp-passkey-link-v1\ndev_abc\n1790000000"
        );
        assert_eq!(
            link_url("https://webmcp.fast/"),
            "https://webmcp.fast/api/v1/device/passkey-link"
        );
    }

    #[test]
    fn refusals_read_as_one_sentence_with_a_hint() {
        let refused = |error: &str, message: Option<&str>| PasskeyError::Refused {
            status: 400,
            error: error.into(),
            message: message.map(str::to_string),
        };
        assert_eq!(
            refused("clock_skew", Some("ts is 400 s off.")).to_string(),
            "passkey link refused: clock_skew (ts is 400 s off). This machine's clock is more than 5 minutes off; correct it and retry."
        );
        assert_eq!(
            refused("invalid_request", None).to_string(),
            "passkey link refused: invalid_request."
        );
        assert_eq!(refused("rate_limited", Some(" ")).code(), "rate_limited");
    }

    #[test]
    fn instructions_name_the_site_and_the_time() {
        let link = |expires_in| PasskeyLink {
            url: "https://alice.webmcp.fast/x".into(),
            expires_in,
        };
        assert_eq!(
            instructions("alice", "https://webmcp.fast", &link(600)),
            "Open this link in the browser where you are signed in to alice.webmcp.fast, within 10 minutes, and add a passkey."
        );
        assert_eq!(
            instructions("bob", "http://localhost:8787", &link(30)),
            "Open this link in the browser where you are signed in to bob.localhost:8787, within 1 minute, and add a passkey."
        );
    }
}
