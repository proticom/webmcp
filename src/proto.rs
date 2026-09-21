//! Relay wire protocol v1 (see `docs/PROTOCOL.md` and
//! `packages/proto/relay.schema.json`).
//!
//! Every JSON frame is tagged by its `t` field. Frames with a `t` the daemon
//! does not know deserialize to [`Frame::Unknown`] and must be ignored.
//! Keep-alive (`ping` / `pong`) is *not* JSON: it is a bare WebSocket text
//! frame, see [`PING`] and [`PONG`].

use serde::{Deserialize, Serialize};

/// Protocol version carried in `hello.v`.
pub const PROTOCOL_VERSION: u32 = 1;

/// Keep-alive text frame sent by the daemon.
pub const PING: &str = "ping";
/// Keep-alive text frame the gateway answers with.
pub const PONG: &str = "pong";

/// Prefix of the message signed during the connect handshake.
pub const CONNECT_SIGN_PREFIX: &str = "webmcp-connect-v1\n";

/// Close code: authentication failed. Stop and pair again.
pub const CLOSE_UNAUTHORIZED: u16 = 4401;
/// Close code: device revoked. Stop and pair again.
pub const CLOSE_REVOKED: u16 = 4403;
/// Close code: protocol violation (frame before `welcome` other than
/// `hello` / `auth`).
pub const CLOSE_BAD_FRAME: u16 = 4400;
/// Close code: unsupported `hello.v`.
pub const CLOSE_BAD_VERSION: u16 = 4406;

/// A relay frame, tagged by `t`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Frame {
    /// daemon → gateway: first frame after the upgrade.
    Hello {
        v: u32,
        device_id: String,
        daemon_version: String,
        platform: String,
    },
    /// gateway → daemon: nonce to sign (base64 string, signed verbatim).
    Challenge { nonce: String },
    /// daemon → gateway: base64 Ed25519 signature.
    Auth { signature: String },
    /// gateway → daemon: handshake complete.
    Welcome {
        handle: String,
        device: String,
        server_time: String,
    },
    /// daemon → gateway: attached servers, on connect and on every change.
    Servers { servers: Vec<ServerInfo> },
    /// either direction: non-fatal unless followed by a close.
    Error {
        code: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// gateway → daemon (M2): an MCP session opened on `/<device>/<server>/mcp`.
    SessionOpen {
        sid: String,
        server: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client: Option<ClientInfo>,
    },
    /// either direction (M2): session ended.
    SessionClose {
        sid: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// either direction (M2): one JSON-RPC message, verbatim, for `sid`.
    Mcp { sid: String, msg: serde_json::Value },
    /// gateway → daemon: the owner removed this server on the dashboard. The
    /// gateway can ask a device to offer less, never more; there is no `attach`.
    Detach { alias: String },
    /// Any `t` this daemon does not know. Ignored.
    #[serde(other)]
    Unknown,
}

impl Frame {
    /// The frame's `t` tag as it appears on the wire.
    pub fn tag(&self) -> &'static str {
        match self {
            Frame::Hello { .. } => "hello",
            Frame::Challenge { .. } => "challenge",
            Frame::Auth { .. } => "auth",
            Frame::Welcome { .. } => "welcome",
            Frame::Servers { .. } => "servers",
            Frame::Error { .. } => "error",
            Frame::SessionOpen { .. } => "session_open",
            Frame::SessionClose { .. } => "session_close",
            Frame::Mcp { .. } => "mcp",
            Frame::Detach { .. } => "detach",
            Frame::Unknown => "unknown",
        }
    }

    /// Serialize to the compact JSON text sent on the wire.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    /// Parse a text frame. Unknown `t` values yield [`Frame::Unknown`];
    /// malformed JSON or a missing `t` is an error.
    pub fn from_json(text: &str) -> serde_json::Result<Frame> {
        serde_json::from_str(text)
    }
}

/// Client metadata carried by `session_open`. Extra keys are preserved.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ClientInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// One attached server as advertised in the `servers` frame.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerInfo {
    pub alias: String,
    pub transport: Transport,
    pub mode: SessionMode,
    pub status: ServerStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// How the daemon talks to a local MCP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    Stdio,
    Http,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            Transport::Stdio => "stdio",
            Transport::Http => "http",
        })
    }
}

/// Session model per server (design doc §3b).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[clap(rename_all = "kebab-case")]
pub enum SessionMode {
    #[default]
    PerSession,
    Shared,
    Exclusive,
}

impl std::fmt::Display for SessionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            SessionMode::PerSession => "per-session",
            SessionMode::Shared => "shared",
            SessionMode::Exclusive => "exclusive",
        })
    }
}

/// Server health as advertised to the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServerStatus {
    Ready,
    Error,
}

/// Build the exact bytes signed in the connect handshake:
/// `"webmcp-connect-v1\n" + device_id + "\n" + nonce`, with `nonce` being
/// the base64 string exactly as received.
pub fn connect_sign_message(device_id: &str, nonce: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(CONNECT_SIGN_PREFIX.len() + device_id.len() + 1 + nonce.len());
    msg.extend_from_slice(CONNECT_SIGN_PREFIX.as_bytes());
    msg.extend_from_slice(device_id.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(nonce.as_bytes());
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_tag_is_ignored_not_an_error() {
        let f = Frame::from_json(r#"{"t":"something_new","x":1}"#).unwrap();
        assert_eq!(f, Frame::Unknown);
    }

    #[test]
    fn missing_tag_is_an_error() {
        assert!(Frame::from_json(r#"{"nonce":"x"}"#).is_err());
        assert!(Frame::from_json("not json").is_err());
    }

    #[test]
    fn optional_fields_are_omitted_when_none() {
        let f = Frame::Error {
            code: "unauthorized".into(),
            message: None,
        };
        assert_eq!(
            f.to_json().unwrap(),
            r#"{"t":"error","code":"unauthorized"}"#
        );
    }

    #[test]
    fn sign_message_layout() {
        let m = connect_sign_message("dev_abc", "QUJD");
        assert_eq!(m, b"webmcp-connect-v1\ndev_abc\nQUJD");
    }

    #[test]
    fn enums_use_kebab_case() {
        let s = ServerInfo {
            alias: "a".into(),
            transport: Transport::Stdio,
            mode: SessionMode::PerSession,
            status: ServerStatus::Ready,
            error: None,
        };
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            r#"{"alias":"a","transport":"stdio","mode":"per-session","status":"ready"}"#
        );
    }
}
