//! Device pairing: `POST /api/v1/pair` (protocol §1).

use std::path::Path;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::config::{self, Config, ServerEntry};
use crate::error::Error;
use crate::{keys, platform};

/// Request body for `POST /api/v1/pair`.
#[derive(Debug, Clone, Serialize)]
pub struct PairRequest {
    pub code: String,
    pub device_name: String,
    /// base64, 32 bytes.
    pub public_key: String,
    /// hex sha256.
    pub hardware_id: String,
    pub daemon_version: String,
    pub platform: String,
}

/// `201` response body. Every field is persisted.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PairResponse {
    pub device_id: String,
    pub handle: String,
    #[serde(default)]
    pub org_id: Option<String>,
    pub relay_url: String,
    pub base_url: String,
    /// The name the device was registered under, if the gateway says so. On
    /// the §1a approval page the human may pick a different one than the
    /// daemon asked for; without this field the requested name is assumed.
    #[serde(default)]
    pub device_name: Option<String>,
}

/// Persist a fresh pairing: the key first (a config without a key is
/// useless, the reverse is harmless), then the config. Shared by `login` and
/// `up`. `servers` carries the attached set over a re-pair.
pub fn persist(
    dir: &Path,
    key: &SigningKey,
    resp: PairResponse,
    requested_name: String,
    hardware_id: String,
    servers: Vec<ServerEntry>,
) -> Result<Config, Error> {
    keys::save(dir, key)?;
    let cfg = Config {
        device_id: resp.device_id,
        handle: resp.handle,
        device_name: resp
            .device_name
            .filter(|n| config::is_valid_alias(n))
            .unwrap_or(requested_name),
        org_id: resp.org_id,
        base_url: resp.base_url,
        relay_url: resp.relay_url,
        hardware_id,
        servers,
    };
    cfg.save_to(dir)?;
    Ok(cfg)
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    message: Option<String>,
}

/// Every documented failure has its own variant so the CLI can print a
/// precise instruction.
#[derive(Debug, thiserror::Error)]
pub enum PairError {
    #[error("the server rejected the request: {0}")]
    InvalidRequest(String),
    #[error(
        "pairing code not found: it is unknown, expired (codes last 10 minutes) or already used"
    )]
    CodeNotFound,
    #[error(
        "device name `{0}` is already used by another device on this handle; pick one with --name"
    )]
    DeviceNameTaken(String),
    #[error("your plan allows no more devices; revoke one in the dashboard or upgrade")]
    DeviceLimit,
    #[error("this machine is already paired to another free handle; revoke it there first")]
    HardwareAlreadyPaired,
    #[error("too many pairing attempts from this address; wait a few minutes and retry")]
    RateLimited,
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

/// Normalize a user-typed code: dashes and case are ignored by the server,
/// but we strip whitespace/dashes and upper-case for a tidy request.
pub fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Pair endpoint for a base URL (trailing slashes tolerated).
pub fn pair_url(base_url: &str) -> String {
    format!("{}/api/v1/pair", base_url.trim_end_matches('/'))
}

/// Call the pair endpoint and map every documented status.
pub async fn pair(base_url: &str, req: &PairRequest) -> Result<PairResponse, PairError> {
    let url = pair_url(base_url);
    let client = reqwest::Client::builder()
        .user_agent(platform::user_agent())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|source| PairError::Transport {
            url: url.clone(),
            source,
        })?;
    let resp = client
        .post(&url)
        .json(req)
        .send()
        .await
        .map_err(|source| PairError::Transport {
            url: url.clone(),
            source,
        })?;
    let status = resp.status();
    let body = resp.text().await.map_err(|source| PairError::Transport {
        url: url.clone(),
        source,
    })?;
    if status == reqwest::StatusCode::CREATED {
        return serde_json::from_str(&body).map_err(|e| PairError::Unexpected {
            status: status.as_u16(),
            url,
            body: format!("could not parse body ({e}): {body}"),
        });
    }
    let err: ErrorBody = serde_json::from_str(&body).unwrap_or(ErrorBody {
        error: String::new(),
        message: None,
    });
    Err(match (status.as_u16(), err.error.as_str()) {
        (400, _) => PairError::InvalidRequest(
            err.message
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| "invalid request".into()),
        ),
        (404, _) => PairError::CodeNotFound,
        (409, "device_name_taken") => PairError::DeviceNameTaken(req.device_name.clone()),
        (409, "device_limit") => PairError::DeviceLimit,
        (409, "hardware_already_paired") => PairError::HardwareAlreadyPaired,
        (429, _) => PairError::RateLimited,
        _ => PairError::Unexpected {
            status: status.as_u16(),
            url,
            body: if body.is_empty() {
                "<empty body>".into()
            } else {
                body
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_normalization() {
        assert_eq!(normalize_code("abcd-efgh"), "ABCDEFGH");
        assert_eq!(normalize_code(" AB CD - EF GH "), "ABCDEFGH");
    }

    #[test]
    fn url_join() {
        assert_eq!(
            pair_url("https://webmcp.fast/"),
            "https://webmcp.fast/api/v1/pair"
        );
        assert_eq!(
            pair_url("http://localhost:8787"),
            "http://localhost:8787/api/v1/pair"
        );
    }
}
