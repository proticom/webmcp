//! Machine-readable output (`--json`) and the public URLs it reports.
//!
//! Contract: in JSON mode a command prints exactly one JSON object on stdout,
//! on one line, and nothing else there; logs stay on stderr. The one
//! exception is `webmcp up` when it has to pair: it first prints one
//! [`ApprovalRequired`] line (the human must act before it can continue),
//! then, at the end, the final [`UpReport`] line. A failure of any command is
//! an [`ErrorReport`] (`up` reports its own, with the same leading fields).
//!
//! Exit codes: 0 ok, 1 error, 2 approval declined, 3 approval expired.

use crate::policy::{Confirm, ToolPolicy};
use serde::Serialize;

use crate::approvals::Agents;
use crate::config::{ApprovedCredential, Config, ServerEntry};
use crate::discover::{Definition, Discovered, Source};
use crate::passkey::PasskeyLink;
use crate::proto::{CredentialKind, SessionMode, Transport};

/// What the human does once `up` is done.
pub const NEXT_CONNECTOR: &str = "Paste a server URL into Claude, ChatGPT or Grok as a custom connector, sign in to webmcp.fast when asked, and click Allow.";

/// `https://<handle>.<base host>/<device>/<alias>/mcp`, the host (and any
/// port) taken from the paired `base_url`. `None` if that is not a URL with
/// a host, which a gateway never sends.
pub fn public_url(base_url: &str, handle: &str, device: &str, alias: &str) -> Option<String> {
    let base = url::Url::parse(base_url).ok()?;
    let host = base.host_str()?;
    let port = base.port().map(|p| format!(":{p}")).unwrap_or_default();
    Some(format!(
        "{}://{handle}.{host}{port}/{device}/{alias}/mcp",
        base.scheme()
    ))
}

/// One line of JSON. Serializing these plain structs cannot fail.
pub fn line<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("report types serialize")
}

/// First line of `up --json` when this machine is not paired yet.
#[derive(Debug, Serialize)]
pub struct ApprovalRequired<'a> {
    pub event: &'static str,
    pub verification_uri_complete: &'a str,
    pub user_code: &'a str,
    pub expires_in: u64,
}

impl<'a> ApprovalRequired<'a> {
    pub fn new(verification_uri_complete: &'a str, user_code: &'a str, expires_in: u64) -> Self {
        ApprovalRequired {
            event: "approval_required",
            verification_uri_complete,
            user_code,
            expires_in,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UpEvent {
    Ready,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceOutcome {
    /// The background service is installed (now or already).
    Installed,
    /// Not installed: not asked for, or declined.
    Skipped,
    /// No background service on this platform.
    Unsupported,
}

/// An attached server and where agents reach it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ServerUrl {
    pub alias: String,
    pub url: Option<String>,
    /// Present on servers attached by this run whose definition had env
    /// variables: their NAMES. The values were copied into the webmcp config.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env_carried: Vec<String>,
}

/// Final line of `up --json`. Every key is always present except `code` and
/// `message`, which appear only when `event` is `error`; `handle` and
/// `device` are null if the failure came before pairing.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UpReport {
    pub event: UpEvent,
    pub handle: Option<String>,
    pub device: Option<String>,
    pub servers: Vec<ServerUrl>,
    pub service: ServiceOutcome,
    pub next: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl UpReport {
    /// The servers of `cfg` with their URLs; `carried` lists `(alias, env
    /// names)` for the ones this run attached.
    pub fn servers_of(cfg: &Config, carried: &[(String, Vec<String>)]) -> Vec<ServerUrl> {
        cfg.servers
            .iter()
            .map(|s| ServerUrl {
                alias: s.alias.clone(),
                url: public_url(&cfg.base_url, &cfg.handle, &cfg.device_name, &s.alias),
                env_carried: carried
                    .iter()
                    .find(|(alias, _)| *alias == s.alias)
                    .map(|(_, names)| names.clone())
                    .unwrap_or_default(),
            })
            .collect()
    }
}

/// Failure of any command in JSON mode. `code` is a protocol error name
/// (`access_denied`, `expired_token`, `device_limit`…) or plain `error`.
#[derive(Debug, Serialize)]
pub struct ErrorReport<'a> {
    pub event: &'static str,
    pub code: &'a str,
    pub message: &'a str,
}

impl<'a> ErrorReport<'a> {
    pub fn new(code: &'a str, message: &'a str) -> Self {
        ErrorReport {
            event: "error",
            code,
            message,
        }
    }
}

/// `discover --json`: `{"servers":[…]}`.
#[derive(Debug, Serialize)]
pub struct DiscoverReport<'a> {
    pub servers: Vec<DiscoveredView<'a>>,
}

/// One discovered server. There is deliberately no field an env value could
/// travel in: `env` holds names only.
#[derive(Debug, Serialize)]
pub struct DiscoveredView<'a> {
    pub name: &'a str,
    /// The alias `up --attach` would give it.
    pub alias: &'a str,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<&'a str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<&'a str>,
    pub attachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    pub sources: &'a [Source],
}

impl<'a> DiscoverReport<'a> {
    pub fn new(found: &'a [Discovered]) -> Self {
        DiscoverReport {
            servers: found.iter().map(DiscoveredView::new).collect(),
        }
    }
}

impl<'a> DiscoveredView<'a> {
    pub fn new(d: &'a Discovered) -> Self {
        let (kind, command, args, url) = match &d.definition {
            Definition::Stdio { command, args, .. } => {
                ("stdio", Some(command.as_str()), Some(args.as_slice()), None)
            }
            Definition::Http { url } => ("http", None, None, Some(url.as_str())),
        };
        DiscoveredView {
            name: &d.name,
            alias: &d.alias,
            kind,
            command,
            args,
            env: command.map(|_| d.env_names()),
            cwd: d.effective_cwd().map(|c| c.display().to_string()),
            url,
            attachable: d.attachable(),
            reason: d.not_attachable(),
            sources: &d.sources,
        }
    }
}

/// `status --json`. Unpaired: only `paired` and `config`.
#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub paired: bool,
    pub config: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Null when `device.key` is missing or unreadable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_fingerprint: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub servers: Option<usize>,
}

/// An attached server in `servers`, `attach` and `detach` output. Env is
/// left out entirely: the config holds values.
#[derive(Debug, Serialize)]
pub struct ServerView {
    pub alias: String,
    pub transport: Transport,
    pub mode: SessionMode,
    pub target: String,
    pub url: Option<String>,
    pub tools: ToolPolicy,
    pub confirm: Confirm,
}

impl ServerView {
    pub fn new(cfg: &Config, s: &ServerEntry) -> Self {
        ServerView {
            alias: s.alias.clone(),
            transport: s.transport,
            mode: s.mode,
            target: s.target().to_string(),
            url: public_url(&cfg.base_url, &cfg.handle, &cfg.device_name, &s.alias),
            tools: s.tools.clone(),
            confirm: s.confirm,
        }
    }
}

/// `servers --json`.
#[derive(Debug, Serialize)]
pub struct ServersReport {
    pub servers: Vec<ServerView>,
}

/// `tools --json` and `confirm --json`: the server after the change.
#[derive(Debug, Serialize)]
pub struct PolicyReport {
    pub server: ServerView,
}

/// `attach --json`.
#[derive(Debug, Serialize)]
pub struct AttachReport {
    pub attached: ServerView,
}

/// `detach --json`.
#[derive(Debug, Serialize)]
pub struct DetachReport {
    pub detached: ServerView,
}

/// `service status --json`. `supported` is false off macOS.
#[derive(Debug, Serialize)]
pub struct ServiceStatusReport {
    pub supported: bool,
    pub installed: bool,
    pub running: bool,
    pub pid: Option<u32>,
    pub log: Option<String>,
}

/// `passkey --json`: the link to open, and for how many seconds it works.
#[derive(Debug, Serialize)]
pub struct PasskeyLinkReport<'a> {
    pub event: &'static str,
    pub url: &'a str,
    pub expires_in: u64,
}

impl<'a> PasskeyLinkReport<'a> {
    pub fn new(link: &'a PasskeyLink) -> Self {
        PasskeyLinkReport {
            event: "passkey_link",
            url: &link.url,
            expires_in: link.expires_in,
        }
    }
}

/// `approvals --json`, and the state `approvals on` and `approvals off`
/// leave. `approved` is what is enforced: empty while approvals are off.
#[derive(Debug, Serialize)]
pub struct ApprovalsReport {
    pub require_approval: bool,
    pub approved: Vec<ApprovedCredential>,
    pub waiting: Vec<WaitingAgent>,
}

/// An agent refused for want of approval and not approved since.
#[derive(Debug, Serialize)]
pub struct WaitingAgent {
    pub id: String,
    pub kind: CredentialKind,
    pub name: String,
    /// The aliases it asked for.
    pub servers: Vec<String>,
    pub last_seen: String,
}

impl ApprovalsReport {
    pub fn new(cfg: &Config, agents: &Agents) -> Self {
        let waiting = agents
            .waiting(cfg)
            .into_iter()
            .map(|(id, seen)| WaitingAgent {
                id: id.to_string(),
                kind: seen.kind,
                name: seen.name.clone(),
                servers: seen.servers.clone(),
                last_seen: seen.last_seen.clone(),
            })
            .collect();
        ApprovalsReport {
            require_approval: cfg.require_approval,
            approved: if cfg.require_approval {
                cfg.approved.clone()
            } else {
                Vec::new()
            },
            waiting,
        }
    }
}

/// `approve --json`: the credentials this run approved.
#[derive(Debug, Serialize)]
pub struct ApproveReport {
    pub approved: Vec<ApprovedCredential>,
}

/// `approvals revoke --json`.
#[derive(Debug, Serialize)]
pub struct RevokeReport {
    pub revoked: ApprovedCredential,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg() -> Config {
        Config {
            device_id: "dev_1".into(),
            handle: "alice".into(),
            device_name: "studio".into(),
            org_id: None,
            base_url: "https://webmcp.fast".into(),
            relay_url: "wss://webmcp.fast/connect".into(),
            hardware_id: "ab".repeat(32),
            require_approval: false,
            servers: vec![
                ServerEntry::stdio("github", "npx -y gh", SessionMode::PerSession).unwrap(),
                ServerEntry::http("web", "http://localhost:3000/mcp", SessionMode::Shared).unwrap(),
            ],
            approved: vec![],
        }
    }

    #[test]
    fn public_urls_follow_the_base_url() {
        assert_eq!(
            public_url("https://webmcp.fast", "alice", "studio", "fs").as_deref(),
            Some("https://alice.webmcp.fast/studio/fs/mcp")
        );
        assert_eq!(
            public_url("https://webmcp.fast/", "alice", "studio", "fs").as_deref(),
            Some("https://alice.webmcp.fast/studio/fs/mcp")
        );
        assert_eq!(
            public_url("http://localhost:8787", "bob", "box", "db").as_deref(),
            Some("http://bob.localhost:8787/box/db/mcp")
        );
        assert_eq!(public_url("not a url", "a", "b", "c"), None);
    }

    #[test]
    fn approval_line_shape() {
        let l = line(&ApprovalRequired::new(
            "https://webmcp.fast/activate?code=ABCD-EFGH",
            "ABCD-EFGH",
            900,
        ));
        assert!(!l.contains('\n'));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&l).unwrap(),
            json!({
                "event": "approval_required",
                "verification_uri_complete": "https://webmcp.fast/activate?code=ABCD-EFGH",
                "user_code": "ABCD-EFGH",
                "expires_in": 900
            })
        );
    }

    #[test]
    fn final_up_object_ready() {
        let cfg = cfg();
        let report = UpReport {
            event: UpEvent::Ready,
            handle: Some(cfg.handle.clone()),
            device: Some(cfg.device_name.clone()),
            servers: UpReport::servers_of(&cfg, &[("github".into(), vec!["GITHUB_TOKEN".into()])]),
            service: ServiceOutcome::Installed,
            next: NEXT_CONNECTOR.into(),
            code: None,
            message: None,
        };
        let l = line(&report);
        assert!(!l.contains('\n'));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&l).unwrap(),
            json!({
                "event": "ready",
                "handle": "alice",
                "device": "studio",
                "servers": [
                    {"alias": "github", "url": "https://alice.webmcp.fast/studio/github/mcp",
                     "env_carried": ["GITHUB_TOKEN"]},
                    {"alias": "web", "url": "https://alice.webmcp.fast/studio/web/mcp"}
                ],
                "service": "installed",
                "next": NEXT_CONNECTOR
            })
        );
    }

    #[test]
    fn final_up_object_error_before_pairing() {
        let report = UpReport {
            event: UpEvent::Error,
            handle: None,
            device: None,
            servers: vec![],
            service: ServiceOutcome::Skipped,
            next: "Run `webmcp up` again.".into(),
            code: Some("access_denied".into()),
            message: Some("declined".into()),
        };
        assert_eq!(
            serde_json::to_value(&report).unwrap(),
            json!({
                "event": "error", "handle": null, "device": null, "servers": [],
                "service": "skipped", "next": "Run `webmcp up` again.",
                "code": "access_denied", "message": "declined"
            })
        );
        assert_eq!(
            serde_json::to_value(ServiceOutcome::Unsupported).unwrap(),
            json!("unsupported")
        );
    }

    #[test]
    fn server_views_have_urls_and_no_env() {
        let mut cfg = cfg();
        cfg.servers[0]
            .env
            .insert("GITHUB_TOKEN".into(), "ghp_secret".into());
        let report = ServersReport {
            servers: cfg
                .servers
                .iter()
                .map(|s| ServerView::new(&cfg, s))
                .collect(),
        };
        let l = line(&report);
        assert!(!l.contains("ghp_secret") && !l.contains("GITHUB_TOKEN"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&l).unwrap()["servers"][0],
            json!({"alias": "github", "transport": "stdio", "mode": "per-session",
                   "target": "npx -y gh", "url": "https://alice.webmcp.fast/studio/github/mcp",
                   "tools": "all", "confirm": "never"})
        );
    }

    #[test]
    fn error_line_shape() {
        assert_eq!(
            serde_json::to_value(ErrorReport::new("error", "boom")).unwrap(),
            json!({"event": "error", "code": "error", "message": "boom"})
        );
    }

    #[test]
    fn approvals_report_shapes() {
        use crate::proto::Credential;
        use std::time::{Duration, UNIX_EPOCH};
        let at = UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        let agent = |id: &str, name: &str| Credential {
            id: id.into(),
            kind: CredentialKind::Oauth,
            name: name.into(),
        };
        let mut agents = Agents::default();
        agents.observe(
            &agent("grt_wait", "Cursor"),
            Some("cursor"),
            "github",
            false,
            at,
        );
        agents.observe(
            &agent("grt_ok", "Claude"),
            Some("claude-ai"),
            "web",
            true,
            at,
        );
        let mut cfg = cfg();
        // Off: nothing is enforced and nothing waits.
        assert_eq!(
            serde_json::to_value(ApprovalsReport::new(&cfg, &agents)).unwrap(),
            json!({"require_approval": false, "approved": [], "waiting": []})
        );

        cfg.require_approval = true;
        cfg.approved = vec![ApprovedCredential {
            id: "grt_ok".into(),
            kind: CredentialKind::Oauth,
            name: "Claude".into(),
            approved_at: "2026-09-21T14:13:20Z".into(),
        }];
        let claude = json!({"id": "grt_ok", "kind": "oauth", "name": "Claude",
                            "approved_at": "2026-09-21T14:13:20Z"});
        let l = line(&ApprovalsReport::new(&cfg, &agents));
        assert!(!l.contains('\n'));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&l).unwrap(),
            json!({
                "require_approval": true,
                "approved": [claude],
                "waiting": [{"id": "grt_wait", "kind": "oauth", "name": "Cursor",
                             "servers": ["github"], "last_seen": "2026-09-21T14:13:20Z"}]
            })
        );
        assert_eq!(
            serde_json::to_value(ApproveReport {
                approved: cfg.approved.clone()
            })
            .unwrap(),
            json!({ "approved": [claude] })
        );
        assert_eq!(
            serde_json::to_value(RevokeReport {
                revoked: cfg.approved[0].clone()
            })
            .unwrap(),
            json!({ "revoked": claude })
        );
    }
}
