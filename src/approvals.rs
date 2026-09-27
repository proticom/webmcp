//! Local approval of new agents: `webmcp approvals` and `webmcp approve`.
//!
//! Two files, one writer each. `config.toml` holds the decision:
//! `require_approval` and the `approved` credentials. The CLI writes it and a
//! running daemon follows it on reload. `agents.json` holds observations:
//! every credential the gateway presented on a `session_open`. Only the
//! running daemon writes it. The CLI reads both and merges them, so a
//! credential approved a moment ago is never listed as waiting.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::config::{write_private, ApprovedCredential, Config};
use crate::error::Error;
use crate::proto::{ClientInfo, Credential, CredentialKind};

/// Name of the observations file inside the config directory.
pub const AGENTS_FILE: &str = "agents.json";
/// Set (to anything) to turn desktop notifications off.
pub const NO_NOTIFY_ENV: &str = "WEBMCP_NO_NOTIFY";
/// `agents.json` keeps this many of the most recently seen credentials.
pub const MAX_AGENTS: usize = 200;
/// A refused credential notifies once, then at most once per this long.
pub const NOTIFY_EVERY: Duration = Duration::from_secs(10 * 60);
/// Client names and aliases kept per credential.
const MAX_NAMES: usize = 16;
/// Longest name kept, in characters.
const MAX_NAME_CHARS: usize = 100;

/// Which credentials may open sessions: what the relay enforces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Admission {
    /// Approvals off: every credential the gateway accepted.
    #[default]
    Open,
    /// Approvals on: only these credential ids.
    Approved(BTreeSet<String>),
}

impl Admission {
    /// True while approvals are on.
    pub fn required(&self) -> bool {
        matches!(self, Admission::Approved(_))
    }

    /// `None` is a session without a credential (an older gateway): admitted
    /// only while approvals are off.
    pub fn admits(&self, credential_id: Option<&str>) -> bool {
        match self {
            Admission::Open => true,
            Admission::Approved(ids) => credential_id.is_some_and(|id| ids.contains(id)),
        }
    }
}

/// What `agents.json` says about one credential: names, never a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentRecord {
    pub kind: CredentialKind,
    pub name: String,
    /// `clientInfo.name` of the harnesses that used it, in the order first seen.
    #[serde(default)]
    pub clients: Vec<String>,
    /// Aliases it asked for, in the order first seen.
    #[serde(default)]
    pub servers: Vec<String>,
    /// RFC 3339 UTC.
    pub first_seen: String,
    pub last_seen: String,
    /// Refused for want of approval and not admitted since.
    #[serde(default)]
    pub waiting: bool,
}

/// `agents.json`: credential id → what was seen.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Agents(BTreeMap<String, AgentRecord>);

impl Agents {
    /// Path of `agents.json` inside `dir`.
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(AGENTS_FILE)
    }

    /// Load `dir/agents.json`. A missing file means nothing was seen yet.
    pub fn load_from(dir: &Path) -> Result<Agents, Error> {
        let path = Self::path_in(dir);
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| Error::Corrupt(format!("{}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Agents::default()),
            Err(e) => Err(Error::io("read agents", &path, e)),
        }
    }

    /// Write `dir/agents.json` atomically, readable by the owner only.
    pub fn save_to(&self, dir: &Path) -> Result<(), Error> {
        let mut text =
            serde_json::to_string_pretty(self).map_err(|e| Error::Corrupt(e.to_string()))?;
        text.push('\n');
        write_private(dir, AGENTS_FILE, text.as_bytes())
    }

    pub fn get(&self, id: &str) -> Option<&AgentRecord> {
        self.0.get(id)
    }

    /// Record one `session_open` that carried `credential`. `admitted` is
    /// false when it was refused for want of approval.
    pub fn observe(
        &mut self,
        credential: &Credential,
        client: Option<&str>,
        alias: &str,
        admitted: bool,
        now: SystemTime,
    ) {
        let now = rfc3339(now);
        let record = self
            .0
            .entry(credential.id.clone())
            .or_insert_with(|| AgentRecord {
                kind: credential.kind,
                name: String::new(),
                clients: Vec::new(),
                servers: Vec::new(),
                first_seen: now.clone(),
                last_seen: now.clone(),
                waiting: false,
            });
        record.kind = credential.kind;
        record.name = clean_name(&credential.name);
        if let Some(client) = client.map(clean_name).filter(|c| !c.is_empty()) {
            remember(&mut record.clients, client);
        }
        remember(&mut record.servers, alias.to_string());
        record.last_seen = now;
        record.waiting = !admitted;
        // The credential just seen stays even if the clock went backwards.
        while self.0.len() > MAX_AGENTS {
            let Some(oldest) = self
                .0
                .iter()
                .filter(|(id, _)| **id != credential.id)
                .min_by(|a, b| a.1.last_seen.cmp(&b.1.last_seen))
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            self.0.remove(&oldest);
        }
    }

    /// Credentials refused for want of approval and not approved since, most
    /// recently seen first. Empty while approvals are off: nothing waits then.
    pub fn waiting<'a>(&'a self, cfg: &Config) -> Vec<(&'a str, &'a AgentRecord)> {
        let admission = cfg.admission();
        recent_first(
            self.0
                .iter()
                .filter(|(id, r)| r.waiting && !admission.admits(Some(id.as_str()))),
        )
    }

    /// What `webmcp approvals on` offers to keep: every credential seen here
    /// that is not waiting, most recently seen first.
    pub fn already_connected(&self) -> Vec<(&str, &AgentRecord)> {
        recent_first(self.0.iter().filter(|(_, r)| !r.waiting))
    }
}

fn recent_first<'a>(
    records: impl Iterator<Item = (&'a String, &'a AgentRecord)>,
) -> Vec<(&'a str, &'a AgentRecord)> {
    let mut list: Vec<(&str, &AgentRecord)> = records.map(|(id, r)| (id.as_str(), r)).collect();
    list.sort_by(|a, b| b.1.last_seen.cmp(&a.1.last_seen));
    list
}

/// Append `name` unless it is there already, keeping the newest `MAX_NAMES`.
fn remember(list: &mut Vec<String>, name: String) {
    if list.contains(&name) {
        return;
    }
    list.push(name);
    if list.len() > MAX_NAMES {
        list.remove(0);
    }
}

/// The running daemon's side: records every credential the gateway presents
/// in `agents.json`, and tells whoever is at the machine when one is
/// refused. One lives as long as the reconnect loop.
pub struct Recorder {
    /// Where `agents.json` goes; `None` keeps observations in memory.
    dir: Option<PathBuf>,
    agents: Agents,
    /// Desktop notifications on.
    notify: bool,
    notified: HashMap<String, Instant>,
}

impl Recorder {
    pub fn new(dir: Option<PathBuf>, notify: bool) -> Self {
        let agents = match dir.as_deref().map(Agents::load_from) {
            Some(Ok(agents)) => agents,
            Some(Err(e)) => {
                warn!(error = %e, "agents.json could not be read; starting it afresh");
                Agents::default()
            }
            None => Agents::default(),
        };
        Recorder {
            dir,
            agents,
            notify,
            notified: HashMap::new(),
        }
    }

    /// One `session_open` that reached the approval check. `admitted` is
    /// false when it was refused with `approval_required`. Best effort: a
    /// file that cannot be written or a missing notifier never touches the
    /// session.
    pub fn seen(
        &mut self,
        credential: Option<&Credential>,
        client: Option<&ClientInfo>,
        alias: &str,
        admitted: bool,
    ) {
        let Some(credential) = credential else {
            return;
        };
        if !is_valid_id(&credential.id) {
            debug!("the credential id is not printable ASCII; not recorded");
            return;
        }
        let client = client.and_then(|c| c.name.as_deref());
        self.agents
            .observe(credential, client, alias, admitted, SystemTime::now());
        if let Some(dir) = &self.dir {
            if let Err(e) = self.agents.save_to(dir) {
                warn!(error = %e, "could not update agents.json");
            }
        }
        if self.notify && !admitted && self.due(&credential.id, Instant::now()) {
            let name = self
                .agents
                .get(&credential.id)
                .map_or("", |r| r.name.as_str());
            notify(notification_text(name, alias));
        }
    }

    /// The first refusal of a credential, then at most one per `NOTIFY_EVERY`.
    fn due(&mut self, id: &str, now: Instant) -> bool {
        self.notified
            .retain(|_, at| now.duration_since(*at) < NOTIFY_EVERY);
        if self.notified.contains_key(id) {
            return false;
        }
        self.notified.insert(id.to_string(), now);
        true
    }
}

/// Printable ASCII, 1 to 128 bytes: the ids the gateway mints, and nothing a
/// terminal would act on when `webmcp approvals` prints it.
pub fn is_valid_id(id: &str) -> bool {
    (1..=128).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_graphic())
}

/// A name from the gateway as it is stored and shown: control characters
/// dropped, trimmed, at most `MAX_NAME_CHARS`.
fn clean_name(raw: &str) -> String {
    let kept: String = raw.chars().filter(|c| !c.is_control()).collect();
    let cut: String = kept.trim().chars().take(MAX_NAME_CHARS).collect();
    cut.trim_end().to_string()
}

fn notification_text(name: &str, alias: &str) -> String {
    // notify-send servers may read the body as markup.
    let name: String = name
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '<' | '>' | '&'))
        .collect();
    let name = match name.trim() {
        "" => "An agent",
        name => name,
    };
    format!("{name} wants to use {alias} on this machine. Run: webmcp approve")
}

/// The notifier for this platform and its argv. The text is passed as data,
/// never through a shell or spliced into a script.
fn notify_command(text: String) -> Option<(&'static str, Vec<String>)> {
    if cfg!(target_os = "macos") {
        let script = [
            "on run argv",
            "display notification (item 1 of argv) with title \"webmcp\"",
            "end run",
        ];
        let mut args: Vec<String> = script
            .iter()
            .flat_map(|line| ["-e".to_string(), line.to_string()])
            .collect();
        // Without `--`, text starting with `-e` would run as AppleScript.
        args.extend(["--".to_string(), text]);
        Some(("osascript", args))
    } else if cfg!(target_os = "linux") {
        Some((
            "notify-send",
            vec!["--".to_string(), "webmcp".to_string(), text],
        ))
    } else {
        None
    }
}

/// Pop a desktop notification without waiting for it. Never under test.
fn notify(text: String) {
    if cfg!(test) {
        return;
    }
    let Some((program, args)) = notify_command(text) else {
        return;
    };
    tokio::spawn(async move {
        let spawned = tokio::process::Command::new(program)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn();
        match spawned {
            Ok(mut child) => {
                let _ = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
            }
            Err(e) => debug!(error = %e, program, "no desktop notification"),
        }
    });
}

/// `t` in RFC 3339 UTC to the second, e.g. `2026-09-21T14:13:20Z`. These
/// strings sort in time order.
fn rfc3339(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rest) = ((secs / 86_400) as i64, secs % 86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

fn approval(id: &str, seen: &AgentRecord, at: &str) -> ApprovedCredential {
    ApprovedCredential {
        id: id.to_string(),
        kind: seen.kind,
        name: seen.name.clone(),
        approved_at: at.to_string(),
    }
}

/// Append an approval for each of `ids` not in `list` yet. Each must be in
/// `agents`: only a credential that tried this machine can be approved.
fn add_approvals(
    list: &mut Vec<ApprovedCredential>,
    agents: &Agents,
    ids: &[String],
    now: SystemTime,
) -> Result<(), Error> {
    let at = rfc3339(now);
    for id in ids {
        if list.iter().any(|a| a.id == *id) {
            continue;
        }
        let seen = agents
            .get(id)
            .ok_or_else(|| Error::UnknownAgent(id.clone()))?;
        list.push(approval(id, seen, &at));
    }
    Ok(())
}

/// `webmcp approvals on`, approving exactly `keep`: usually what
/// [`Agents::already_connected`] listed, or nothing. Returns false, changing
/// nothing, when approvals were on already.
pub fn turn_on(dir: &Path, keep: &[String], now: SystemTime) -> Result<bool, Error> {
    let mut cfg = Config::load_from(dir)?;
    if cfg.require_approval {
        return Ok(false);
    }
    let agents = Agents::load_from(dir)?;
    cfg.approved.clear();
    add_approvals(&mut cfg.approved, &agents, keep, now)?;
    cfg.require_approval = true;
    cfg.save_to(dir)?;
    Ok(true)
}

/// `webmcp approvals off`. The approved list goes with it, so turning
/// approvals on again starts from the agents seen by then. Returns false,
/// changing nothing, when approvals were off already.
pub fn turn_off(dir: &Path) -> Result<bool, Error> {
    let mut cfg = Config::load_from(dir)?;
    if !cfg.require_approval {
        return Ok(false);
    }
    cfg.require_approval = false;
    cfg.approved.clear();
    cfg.save_to(dir)?;
    Ok(true)
}

/// `webmcp approve`: approve these credentials. Each must have tried to use
/// this machine (be in `agents.json`) or be approved already; nothing is
/// written otherwise. Returns the newly approved ones.
pub fn approve(
    dir: &Path,
    ids: &[String],
    now: SystemTime,
) -> Result<Vec<ApprovedCredential>, Error> {
    let mut cfg = Config::load_from(dir)?;
    if !cfg.require_approval {
        return Err(Error::ApprovalsOff);
    }
    let agents = Agents::load_from(dir)?;
    let before = cfg.approved.len();
    add_approvals(&mut cfg.approved, &agents, ids, now)?;
    let added = cfg.approved[before..].to_vec();
    if !added.is_empty() {
        cfg.save_to(dir)?;
    }
    Ok(added)
}

/// `webmcp approvals revoke`: withdraw one approval. A running daemon ends
/// that credential's sessions on its next reload.
pub fn revoke(dir: &Path, id: &str) -> Result<ApprovedCredential, Error> {
    let mut cfg = Config::load_from(dir)?;
    let idx = cfg
        .approved
        .iter()
        .position(|a| a.id == id)
        .ok_or_else(|| Error::NotApproved(id.to_string()))?;
    let revoked = cfg.approved.remove(idx);
    cfg.save_to(dir)?;
    Ok(revoked)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-09-21T14:13:20Z.
    const T0: u64 = 1_790_000_000;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn cred(id: &str, name: &str) -> Credential {
        Credential {
            id: id.into(),
            kind: CredentialKind::Oauth,
            name: name.into(),
        }
    }

    fn approved(id: &str, approved_at: &str) -> ApprovedCredential {
        ApprovedCredential {
            id: id.into(),
            kind: CredentialKind::Oauth,
            name: format!("agent {id}"),
            approved_at: approved_at.into(),
        }
    }

    /// A paired config dir, approvals on or off, and these observations
    /// (`(id, waiting)`), one second apart in this order.
    fn machine(require_approval: bool, seen: &[(&str, bool)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        Config {
            device_id: "dev_0123456789abcdef".into(),
            handle: "alice".into(),
            device_name: "macbook".into(),
            org_id: None,
            base_url: "https://webmcp.fast".into(),
            relay_url: "wss://webmcp.fast/connect".into(),
            hardware_id: "ab".repeat(32),
            require_approval,
            servers: vec![],
            approved: vec![],
        }
        .save_to(dir.path())
        .unwrap();
        let mut agents = Agents::default();
        for (i, (id, waiting)) in seen.iter().enumerate() {
            let name = format!("agent {id}");
            agents.observe(
                &cred(id, &name),
                Some("h"),
                "fs",
                !waiting,
                at(T0 + i as u64),
            );
        }
        agents.save_to(dir.path()).unwrap();
        dir
    }

    fn config(dir: &tempfile::TempDir) -> Config {
        Config::load_from(dir.path()).unwrap()
    }

    #[test]
    fn admission_rules() {
        assert!(Admission::Open.admits(Some("grt_1")));
        assert!(Admission::Open.admits(None));
        assert!(!Admission::Open.required());
        let on = Admission::Approved(["grt_1".to_string()].into());
        assert!(on.required());
        assert!(on.admits(Some("grt_1")));
        assert!(!on.admits(Some("grt_2")));
        assert!(!on.admits(None));
        assert!(!Admission::Approved(BTreeSet::new()).admits(Some("grt_1")));
    }

    #[test]
    fn rfc3339_agrees_with_date() {
        for (secs, text) in [
            (0, "1970-01-01T00:00:00Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (1_000_000_000, "2001-09-09T01:46:40Z"),
            (1_709_251_199, "2024-02-29T23:59:59Z"),
            (1_709_251_200, "2024-03-01T00:00:00Z"),
            (T0, "2026-09-21T14:13:20Z"),
            (4_102_444_800, "2100-01-01T00:00:00Z"),
        ] {
            assert_eq!(rfc3339(at(secs)), text, "{secs}");
        }
    }

    #[test]
    fn observe_records_what_the_gateway_said() {
        let mut agents = Agents::default();
        let hostile = cred("grt_1", "Claude\u{1b}[31m desktop\n");
        agents.observe(&hostile, Some("claude-ai"), "fs", false, at(T0));
        assert_eq!(
            agents.get("grt_1"),
            Some(&AgentRecord {
                kind: CredentialKind::Oauth,
                name: "Claude[31m desktop".into(),
                clients: vec!["claude-ai".into()],
                servers: vec!["fs".into()],
                first_seen: "2026-09-21T14:13:20Z".into(),
                last_seen: "2026-09-21T14:13:20Z".into(),
                waiting: true,
            })
        );

        // Seen again, admitted this time, from another harness and alias.
        let renamed = Credential {
            kind: CredentialKind::Token,
            ..cred("grt_1", "Claude")
        };
        agents.observe(&renamed, Some("cursor"), "github", true, at(T0 + 60));
        agents.observe(&renamed, Some("claude-ai"), "fs", true, at(T0 + 61));
        assert_eq!(
            agents.get("grt_1"),
            Some(&AgentRecord {
                kind: CredentialKind::Token,
                name: "Claude".into(),
                clients: vec!["claude-ai".into(), "cursor".into()],
                servers: vec!["fs".into(), "github".into()],
                first_seen: "2026-09-21T14:13:20Z".into(),
                last_seen: "2026-09-21T14:14:21Z".into(),
                waiting: false,
            })
        );
    }

    #[test]
    fn observe_keeps_the_most_recently_seen() {
        let mut agents = Agents::default();
        for i in 0..=MAX_AGENTS as u64 {
            agents.observe(&cred(&format!("id{i}"), "a"), None, "fs", true, at(T0 + i));
        }
        assert_eq!(agents.0.len(), MAX_AGENTS);
        assert!(agents.get("id0").is_none());
        assert!(agents.get("id1").is_some() && agents.get("id200").is_some());
        // A clock that went backwards does not cost the newest arrival.
        agents.observe(&cred("late", "a"), None, "fs", false, at(T0 - 1_000));
        assert_eq!(agents.0.len(), MAX_AGENTS);
        assert!(agents.get("late").is_some());
        assert!(agents.get("id1").is_none());
    }

    #[test]
    fn recorder_records_printable_ids_only_in_an_owner_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = Recorder::new(Some(dir.path().to_path_buf()), false);
        r.seen(None, None, "fs", false);
        assert!(!Agents::path_in(dir.path()).exists());
        for bad in ["", "grt 1", "grt_\u{1b}1", &"a".repeat(129)] {
            r.seen(Some(&cred(bad, "x")), None, "fs", false);
        }
        let client = ClientInfo {
            name: Some("claude-ai".into()),
            ..Default::default()
        };
        r.seen(Some(&cred("grt_ok", "Claude")), Some(&client), "fs", false);
        let back = Agents::load_from(dir.path()).unwrap();
        assert_eq!(back.0.keys().collect::<Vec<_>>(), ["grt_ok"]);
        let rec = back.get("grt_ok").unwrap();
        assert_eq!(
            (rec.waiting, rec.clients.as_slice()),
            (true, &["claude-ai".to_string()][..])
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(Agents::path_in(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // A file that no longer parses is started afresh, not fatal.
        std::fs::write(Agents::path_in(dir.path()), "{not json").unwrap();
        let mut r = Recorder::new(Some(dir.path().to_path_buf()), false);
        r.seen(Some(&cred("grt_2", "B")), None, "fs", true);
        let back = Agents::load_from(dir.path()).unwrap();
        assert_eq!(back.0.keys().collect::<Vec<_>>(), ["grt_2"]);
    }

    #[test]
    fn notifications_are_throttled_per_credential() {
        let mut r = Recorder::new(None, false);
        let t0 = Instant::now();
        let min = |m: u64| t0 + Duration::from_secs(60 * m);
        assert!(r.due("a", t0));
        assert!(!r.due("a", min(5)));
        assert!(r.due("b", min(5)));
        assert!(r.due("a", min(10)));
        assert!(!r.due("a", min(19)));
        assert!(r.due("b", min(15)));
    }

    #[test]
    fn notifications_carry_plain_text_as_data() {
        assert_eq!(
            notification_text("Claude <b>&</b>\u{7}", "fs"),
            "Claude b/b wants to use fs on this machine. Run: webmcp approve"
        );
        assert_eq!(
            notification_text(" \n", "fs"),
            "An agent wants to use fs on this machine. Run: webmcp approve"
        );
        let text = "-e do shell script \"x\"".to_string();
        let platform = if cfg!(target_os = "macos") {
            Some("osascript")
        } else if cfg!(target_os = "linux") {
            Some("notify-send")
        } else {
            None
        };
        let command = notify_command(text.clone());
        assert_eq!(command.as_ref().map(|(program, _)| *program), platform);
        if let Some((_, args)) = command {
            assert_eq!(args[args.len() - 2], "--");
            assert_eq!(args[args.len() - 1], text);
            assert_eq!(args.iter().filter(|a| **a == text).count(), 1);
        }
    }

    #[test]
    fn waiting_is_what_was_refused_minus_what_is_approved() {
        let dir = machine(true, &[("a", true), ("b", true), ("c", false)]);
        let waiting = |dir: &tempfile::TempDir| {
            let agents = Agents::load_from(dir.path()).unwrap();
            let ids: Vec<String> = agents
                .waiting(&config(dir))
                .into_iter()
                .map(|(id, _)| id.to_string())
                .collect();
            ids
        };
        assert_eq!(waiting(&dir), ["b", "a"]);
        approve(dir.path(), &["a".to_string()], at(T0 + 9)).unwrap();
        assert_eq!(waiting(&dir), ["b"]);
        turn_off(dir.path()).unwrap();
        assert!(waiting(&dir).is_empty());
    }

    fn already_connected(dir: &tempfile::TempDir) -> Vec<String> {
        let agents = Agents::load_from(dir.path()).unwrap();
        let ids = agents.already_connected();
        ids.into_iter().map(|(id, _)| id.to_string()).collect()
    }

    #[test]
    fn turning_on_keeps_the_agents_that_already_connected() {
        let dir = machine(false, &[("a", false), ("b", true), ("c", false)]);
        // Every agent seen and not waiting, most recently seen first.
        let keep = already_connected(&dir);
        assert_eq!(keep, ["c", "a"]);
        assert!(turn_on(dir.path(), &keep, at(T0 + 100)).unwrap());
        let cfg = config(&dir);
        assert!(cfg.require_approval);
        let at_100 = "2026-09-21T14:15:00Z";
        assert_eq!(cfg.approved, [approved("c", at_100), approved("a", at_100)]);

        // Already on: nothing changes, whatever `keep` says.
        assert!(!turn_on(dir.path(), &[], at(T0 + 200)).unwrap());
        assert_eq!(config(&dir), cfg);
    }

    #[test]
    fn turning_on_without_keep_approves_nobody() {
        let dir = machine(false, &[("a", false), ("b", true)]);
        assert!(turn_on(dir.path(), &[], at(T0)).unwrap());
        let cfg = config(&dir);
        assert!(cfg.require_approval && cfg.approved.is_empty());
    }

    #[test]
    fn turning_on_with_an_unknown_id_changes_nothing() {
        let dir = machine(false, &[("a", false)]);
        let keep = ["a".to_string(), "nope".to_string()];
        assert!(matches!(
            turn_on(dir.path(), &keep, at(T0)),
            Err(Error::UnknownAgent(id)) if id == "nope"
        ));
        let cfg = config(&dir);
        assert!(!cfg.require_approval && cfg.approved.is_empty());
    }

    #[test]
    fn turning_off_forgets_approvals() {
        let dir = machine(false, &[("a", false)]);
        turn_on(dir.path(), &already_connected(&dir), at(T0)).unwrap();
        assert_eq!(config(&dir).approved.len(), 1);
        assert!(turn_off(dir.path()).unwrap());
        let cfg = config(&dir);
        assert!(!cfg.require_approval && cfg.approved.is_empty());
        let text = std::fs::read_to_string(Config::path_in(dir.path())).unwrap();
        assert!(!text.contains("approv"), "{text}");
        assert!(!turn_off(dir.path()).unwrap());
    }

    #[test]
    fn approve_takes_known_ids_once_and_writes_nothing_on_an_unknown_one() {
        let dir = machine(true, &[("a", true), ("b", true), ("c", true)]);
        let ids = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            approve(dir.path(), &ids(&["a"]), at(T0)).unwrap(),
            [approved("a", "2026-09-21T14:13:20Z")]
        );
        assert_eq!(
            approve(dir.path(), &ids(&["a", "b", "b"]), at(T0 + 1)).unwrap(),
            [approved("b", "2026-09-21T14:13:21Z")]
        );
        let before = config(&dir);
        assert!(matches!(
            approve(dir.path(), &ids(&["c", "nope"]), at(T0 + 2)),
            Err(Error::UnknownAgent(id)) if id == "nope"
        ));
        assert_eq!(config(&dir), before);
        assert_eq!(
            before.approved,
            [
                approved("a", "2026-09-21T14:13:20Z"),
                approved("b", "2026-09-21T14:13:21Z")
            ]
        );
    }

    #[test]
    fn approve_needs_approvals_on() {
        let dir = machine(false, &[("a", false)]);
        assert!(matches!(
            approve(dir.path(), &["a".to_string()], at(T0)),
            Err(Error::ApprovalsOff)
        ));
        assert!(config(&dir).approved.is_empty());
    }

    #[test]
    fn revoke_withdraws_one_approval() {
        let dir = machine(true, &[("a", true), ("b", true)]);
        approve(dir.path(), &["a".to_string(), "b".to_string()], at(T0)).unwrap();
        assert_eq!(
            revoke(dir.path(), "a").unwrap(),
            approved("a", "2026-09-21T14:13:20Z")
        );
        assert_eq!(
            config(&dir).approved,
            [approved("b", "2026-09-21T14:13:20Z")]
        );
        assert!(matches!(revoke(dir.path(), "a"), Err(Error::NotApproved(id)) if id == "a"));
    }
}
