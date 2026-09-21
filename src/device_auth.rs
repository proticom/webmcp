//! Pairing without the dashboard: the device authorization flow behind
//! `webmcp up` (protocol §1a, shaped after RFC 8628).
//!
//! [`start`] registers the public key and returns a link for the human;
//! [`wait`] polls until they approve, decline or the code expires. The login
//! code never passes through here.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::pair::PairResponse;
use crate::platform;

/// Seconds added to the poll interval on `slow_down`.
pub const SLOW_DOWN_SECS: u64 = 5;

/// Request body for `POST /api/v1/device/start`.
#[derive(Debug, Clone, Serialize)]
pub struct StartRequest {
    pub device_name: String,
    /// base64, 32 bytes.
    pub public_key: String,
    /// hex sha256.
    pub hardware_id: String,
    pub daemon_version: String,
    pub platform: String,
}

/// `200` body of `device/start`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct StartResponse {
    /// Opaque; the daemon's secret for polling. Never printed.
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    /// Seconds until the codes expire.
    pub expires_in: u64,
    /// Minimum seconds between polls.
    pub interval: u64,
}

#[derive(Debug, Serialize)]
struct PollRequest<'a> {
    device_code: &'a str,
}

#[derive(Debug, Default, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: Option<String>,
}

/// How long one protocol second lasts. Real time in production; tests shrink
/// it so a whole pending → slow_down → approved run takes milliseconds.
#[derive(Debug, Clone, Copy)]
pub struct PollTiming {
    pub second: Duration,
}

impl Default for PollTiming {
    fn default() -> Self {
        PollTiming {
            second: Duration::from_secs(1),
        }
    }
}

/// Every documented way the flow ends without a pairing.
#[derive(Debug, thiserror::Error)]
pub enum DeviceAuthError {
    #[error("the server rejected the request: {0}")]
    InvalidRequest(String),
    #[error("too many pairing attempts from this address; wait a few minutes and retry")]
    RateLimited,
    #[error("the request was declined in the browser; nothing was paired")]
    AccessDenied,
    #[error("the approval link expired before anyone approved it; run `webmcp up` again")]
    Expired,
    #[error(
        "device name `{0}` is already used by another device on this handle; pick one with --name"
    )]
    DeviceNameTaken(String),
    #[error("your plan allows no more devices; revoke one in the dashboard or upgrade")]
    DeviceLimit,
    #[error("this machine is already paired to another free handle; revoke it there first")]
    HardwareAlreadyPaired,
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

impl DeviceAuthError {
    /// Process exit code: 2 declined, 3 expired, 1 anything else.
    pub fn exit_code(&self) -> i32 {
        match self {
            DeviceAuthError::AccessDenied => 2,
            DeviceAuthError::Expired => 3,
            _ => 1,
        }
    }

    /// Stable machine-readable name, the protocol's own where it has one.
    pub fn code(&self) -> &'static str {
        match self {
            DeviceAuthError::InvalidRequest(_) => "invalid_request",
            DeviceAuthError::RateLimited => "rate_limited",
            DeviceAuthError::AccessDenied => "access_denied",
            DeviceAuthError::Expired => "expired_token",
            DeviceAuthError::DeviceNameTaken(_) => "device_name_taken",
            DeviceAuthError::DeviceLimit => "device_limit",
            DeviceAuthError::HardwareAlreadyPaired => "hardware_already_paired",
            DeviceAuthError::Unexpected { .. } => "unexpected_response",
            DeviceAuthError::Transport { .. } => "network",
        }
    }
}

pub fn start_url(base_url: &str) -> String {
    format!("{}/api/v1/device/start", base_url.trim_end_matches('/'))
}

pub fn poll_url(base_url: &str) -> String {
    format!("{}/api/v1/device/poll", base_url.trim_end_matches('/'))
}

fn client(url: &str) -> Result<reqwest::Client, DeviceAuthError> {
    reqwest::Client::builder()
        .user_agent(platform::user_agent())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|source| DeviceAuthError::Transport {
            url: url.to_string(),
            source,
        })
}

/// POST `body` and return status and text; only transport failures are errors.
async fn post<B: Serialize>(
    client: &reqwest::Client,
    url: &str,
    body: &B,
) -> Result<(u16, String), DeviceAuthError> {
    let transport = |source| DeviceAuthError::Transport {
        url: url.to_string(),
        source,
    };
    let resp = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(transport)?;
    let status = resp.status().as_u16();
    let text = resp.text().await.map_err(transport)?;
    Ok((status, text))
}

fn unexpected(status: u16, url: &str, body: String) -> DeviceAuthError {
    DeviceAuthError::Unexpected {
        status,
        url: url.to_string(),
        body: if body.is_empty() {
            "<empty body>".into()
        } else {
            body
        },
    }
}

/// Begin the flow. The key pair exists before this call, so the approval
/// binds to this machine's public key.
pub async fn start(base_url: &str, req: &StartRequest) -> Result<StartResponse, DeviceAuthError> {
    let url = start_url(base_url);
    let (status, body) = post(&client(&url)?, &url, req).await?;
    if status == 200 {
        return serde_json::from_str(&body)
            .map_err(|e| unexpected(status, &url, format!("could not parse body ({e}): {body}")));
    }
    let err: ErrorBody = serde_json::from_str(&body).unwrap_or_default();
    Err(match status {
        400 => DeviceAuthError::InvalidRequest(
            err.message
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| "invalid request".into()),
        ),
        429 => DeviceAuthError::RateLimited,
        _ => unexpected(status, &url, body),
    })
}

/// What one poll said.
enum Poll {
    Approved(Box<PairResponse>),
    Pending,
    SlowDown,
}

async fn poll_once(
    client: &reqwest::Client,
    url: &str,
    device_code: &str,
    device_name: &str,
) -> Result<Poll, DeviceAuthError> {
    let (status, body) = post(client, url, &PollRequest { device_code }).await?;
    if status == 200 {
        return serde_json::from_str(&body)
            .map(|r| Poll::Approved(Box::new(r)))
            .map_err(|e| unexpected(status, url, format!("could not parse body ({e}): {body}")));
    }
    let err: ErrorBody = serde_json::from_str(&body).unwrap_or_default();
    match (status, err.error.as_str()) {
        (400, "authorization_pending") => Ok(Poll::Pending),
        // §1a has no 429 on poll; if an edge rate limiter sends one anyway,
        // backing off is the only sensible reading.
        (400, "slow_down") | (429, _) => Ok(Poll::SlowDown),
        (400, "access_denied") => Err(DeviceAuthError::AccessDenied),
        (400, "expired_token") => Err(DeviceAuthError::Expired),
        (400, "invalid_request") => Err(DeviceAuthError::InvalidRequest(
            err.message.unwrap_or_else(|| "invalid request".into()),
        )),
        (409, "device_name_taken") => Err(DeviceAuthError::DeviceNameTaken(device_name.into())),
        (409, "device_limit") => Err(DeviceAuthError::DeviceLimit),
        (409, "hardware_already_paired") => Err(DeviceAuthError::HardwareAlreadyPaired),
        _ => Err(unexpected(status, url, body)),
    }
}

/// Poll until the human approves or the flow ends. Never polls faster than
/// `interval` (plus 5 s per `slow_down`), and gives up locally once
/// `expires_in` has passed even if the gateway never says `expired_token`.
/// Network blips and 5xx answers are retried until then.
pub async fn wait(
    base_url: &str,
    started: &StartResponse,
    device_name: &str,
    timing: PollTiming,
) -> Result<PairResponse, DeviceAuthError> {
    let url = poll_url(base_url);
    let client = client(&url)?;
    let secs = |n: u64| timing.second.saturating_mul(n.min(u32::MAX as u64) as u32);
    let deadline = tokio::time::Instant::now() + secs(started.expires_in);
    let mut interval = started.interval.max(1);
    loop {
        let wake = tokio::time::Instant::now() + secs(interval);
        if wake > deadline {
            return Err(DeviceAuthError::Expired);
        }
        tokio::time::sleep_until(wake).await;
        match poll_once(&client, &url, &started.device_code, device_name).await {
            Ok(Poll::Approved(resp)) => return Ok(*resp),
            Ok(Poll::Pending) => debug!("authorization pending"),
            Ok(Poll::SlowDown) => {
                interval = interval.saturating_add(SLOW_DOWN_SECS);
                debug!(interval, "gateway asked to slow down");
            }
            Err(e @ DeviceAuthError::Transport { .. }) => {
                warn!(error = %e, "poll failed; retrying")
            }
            Err(DeviceAuthError::Unexpected { status, body, .. }) if status >= 500 => {
                warn!(status, %body, "gateway error while polling; retrying")
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_join() {
        assert_eq!(
            start_url("https://webmcp.fast/"),
            "https://webmcp.fast/api/v1/device/start"
        );
        assert_eq!(
            poll_url("http://localhost:8787"),
            "http://localhost:8787/api/v1/device/poll"
        );
    }

    #[test]
    fn exit_codes_and_names() {
        assert_eq!(DeviceAuthError::AccessDenied.exit_code(), 2);
        assert_eq!(DeviceAuthError::Expired.exit_code(), 3);
        assert_eq!(DeviceAuthError::DeviceLimit.exit_code(), 1);
        assert_eq!(DeviceAuthError::Expired.code(), "expired_token");
        assert_eq!(DeviceAuthError::DeviceLimit.code(), "device_limit");
    }
}
