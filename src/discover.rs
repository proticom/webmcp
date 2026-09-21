//! Find MCP servers other tools on this machine are already configured with,
//! so `webmcp up` can offer them instead of asking for a command line.
//!
//! Strictly read-only, and only ever these files:
//!
//! | Client | Files |
//! |---|---|
//! | Claude Code | `~/.claude.json` (`mcpServers`, `projects.<path>.mcpServers`), `./.mcp.json` |
//! | Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `~/.config/Claude/claude_desktop_config.json` (Linux) |
//! | Cursor | `~/.cursor/mcp.json`, `./.cursor/mcp.json` |
//! | Codex CLI | `~/.codex/config.toml` (`[mcp_servers.<name>]`) |
//! | VS Code | `./.vscode/mcp.json` (`servers`) |
//!
//! A missing or malformed file is skipped. Env VALUES are secrets (API keys):
//! they are kept in memory so `attach` can carry them into the webmcp config,
//! but nothing here prints, logs, serializes or `Debug`-formats them.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::Value;
use tracing::debug;

use crate::config::{self, ServerEntry};
use crate::error::Error;
use crate::proto::SessionMode;

/// Shown for http entries that do not point at this machine.
pub const REMOTE_NOT_ATTACHABLE: &str = "remote, not attachable";

/// Where to look. Injected so tests never read the real home directory.
#[derive(Debug, Clone)]
pub struct Roots {
    pub home: PathBuf,
    pub cwd: PathBuf,
}

impl Roots {
    /// `$HOME` and the current directory.
    pub fn from_env() -> Option<Roots> {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)?;
        let cwd = std::env::current_dir().ok()?;
        Some(Roots { home, cwd })
    }
}

/// One file (and, for Claude Code projects, one project) a definition was
/// found in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Source {
    /// `claude-code`, `claude-desktop`, `cursor`, `codex` or `vscode`.
    pub client: &'static str,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

/// A normalized server definition.
#[derive(Clone, PartialEq, Eq)]
pub enum Definition {
    Stdio {
        command: String,
        args: Vec<String>,
        /// Values are secrets; see the module docs.
        env: BTreeMap<String, String>,
        cwd: Option<PathBuf>,
    },
    Http {
        url: String,
    },
}

// Hand-written so `{:?}` in a log line or a panic can never leak a key.
impl fmt::Debug for Definition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Definition::Stdio {
                command,
                args,
                env,
                cwd,
            } => f
                .debug_struct("Stdio")
                .field("command", command)
                .field("args", args)
                .field("env_names", &env.keys().collect::<Vec<_>>())
                .field("cwd", cwd)
                .finish(),
            Definition::Http { url } => f.debug_struct("Http").field("url", url).finish(),
        }
    }
}

/// A discovered server: one definition, every place it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// The name it has in the source file(s).
    pub name: String,
    /// The alias it would get here: sanitized, unique within one discovery.
    pub alias: String,
    pub definition: Definition,
    pub sources: Vec<Source>,
    /// Set when the first source is project-scoped: that project's
    /// directory. Those clients start the server there, so relative paths
    /// in the command only work from it.
    pub project_dir: Option<PathBuf>,
}

impl Discovered {
    /// `None` when the daemon could relay it; otherwise why not.
    pub fn not_attachable(&self) -> Option<&'static str> {
        match &self.definition {
            Definition::Stdio { .. } => None,
            Definition::Http { url } => config::validate_local_http_url(url)
                .is_err()
                .then_some(REMOTE_NOT_ATTACHABLE),
        }
    }

    /// `stdio` or `http`.
    pub fn kind(&self) -> &'static str {
        match self.definition {
            Definition::Stdio { .. } => "stdio",
            Definition::Http { .. } => "http",
        }
    }

    pub fn attachable(&self) -> bool {
        self.not_attachable().is_none()
    }

    /// Names (never values) of the env variables an attach would carry over.
    pub fn env_names(&self) -> Vec<&str> {
        match &self.definition {
            Definition::Stdio { env, .. } => env.keys().map(String::as_str).collect(),
            Definition::Http { .. } => Vec::new(),
        }
    }

    /// The working directory an attach would use.
    pub fn effective_cwd(&self) -> Option<&Path> {
        match &self.definition {
            Definition::Stdio { cwd: Some(c), .. } => Some(c),
            Definition::Stdio { cwd: None, .. } => {
                self.project_dir.as_deref().filter(|d| d.is_dir())
            }
            Definition::Http { .. } => None,
        }
    }

    /// Command or URL, for display.
    pub fn target(&self) -> String {
        match &self.definition {
            Definition::Stdio { command, args, .. } => {
                shell_words::join(std::iter::once(command).chain(args))
            }
            Definition::Http { url } => url.clone(),
        }
    }

    /// The config entry for this server under `alias`. For stdio the env is
    /// carried over, values included: that is how the server gets its keys.
    pub fn to_entry(&self, alias: &str, mode: SessionMode) -> Result<ServerEntry, Error> {
        match &self.definition {
            Definition::Stdio { env, .. } => {
                let mut entry = ServerEntry::stdio(alias, &self.target(), mode)?;
                entry.env = env.clone();
                entry.cwd = self.effective_cwd().map(Path::to_path_buf);
                Ok(entry)
            }
            Definition::Http { url } => ServerEntry::http(alias, url, mode),
        }
    }
}

/// Sanitize a server name into the alias rules (`^[a-z0-9][a-z0-9-]{0,31}$`):
/// lowercase, runs of anything else become one dash, no dash at either end.
pub fn sanitize_alias(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = true; // suppress leading dashes
    for ch in name.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    out.truncate(32);
    let trimmed = out.trim_end_matches('-');
    if trimmed.is_empty() {
        "server".to_string()
    } else {
        trimmed.to_string()
    }
}

/// `base`, or `base-2`, `base-3`… if taken; the base is shortened so the
/// result still fits in 32 characters.
fn unique_alias(base: &str, taken: &[String]) -> String {
    if !taken.iter().any(|t| t == base) {
        return base.to_string();
    }
    (2u32..)
        .map(|n| {
            let suffix = format!("-{n}");
            let keep = base.len().min(32 - suffix.len());
            format!("{}{suffix}", base[..keep].trim_end_matches('-'))
        })
        .find(|candidate| !taken.iter().any(|t| t == candidate))
        .expect("an unbounded counter always finds a free alias")
}

/// The entry `--attach <wanted>` means: an exact alias first, else the one
/// attachable entry with that name.
pub fn resolve<'a>(found: &'a [Discovered], wanted: &str) -> Result<&'a Discovered, Error> {
    let invalid = |reason: String| Error::Invalid {
        field: "--attach",
        reason,
    };
    let refuse = |d: &'a Discovered| match d.not_attachable() {
        None => Ok(d),
        Some(why) => Err(invalid(format!("`{wanted}` is {why}"))),
    };
    if let Some(d) = found.iter().find(|d| d.alias == wanted) {
        return refuse(d);
    }
    let named: Vec<&Discovered> = found.iter().filter(|d| d.name == wanted).collect();
    let attachable: Vec<&Discovered> = named.iter().copied().filter(|d| d.attachable()).collect();
    match (named.as_slice(), attachable.as_slice()) {
        ([], _) => Err(invalid(format!(
            "no discovered server is called `{wanted}`; run `webmcp discover` to list them"
        ))),
        (_, [one]) => Ok(one),
        ([first, ..], []) => refuse(first),
        (_, many) => Err(invalid(format!(
            "`{wanted}` has {} different definitions; pick one by alias: {}",
            many.len(),
            many.iter()
                .map(|d| d.alias.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// Parse an interactive choice over `count` numbered entries: `1,3`, `2 4`,
/// `all`, or nothing for none. Returns zero-based indexes, in order, once each.
pub fn parse_selection(input: &str, count: usize) -> Result<Vec<usize>, String> {
    let input = input.trim();
    if input.is_empty() || input.eq_ignore_ascii_case("none") {
        return Ok(Vec::new());
    }
    if input.eq_ignore_ascii_case("all") {
        return Ok((0..count).collect());
    }
    let mut picked = Vec::new();
    for token in input.split(|c: char| c == ',' || c.is_whitespace()) {
        if token.is_empty() {
            continue;
        }
        let n: usize = token
            .parse()
            .map_err(|_| format!("`{token}` is not a number"))?;
        if n == 0 || n > count {
            return Err(format!("`{n}` is not between 1 and {count}"));
        }
        if !picked.contains(&(n - 1)) {
            picked.push(n - 1);
        }
    }
    Ok(picked)
}

/// Read every known file under `roots` and return the de-duplicated servers,
/// in file order (the list above), by name within a file.
pub fn discover(roots: &Roots) -> Vec<Discovered> {
    let mut found: Vec<Discovered> = Vec::new();
    let mut add = |name: &str, definition: Definition, source: Source, dir: Option<&Path>| {
        // Identical name and definition in several files is one server.
        if let Some(existing) = found
            .iter_mut()
            .find(|d| d.name == name && d.definition == definition)
        {
            if !existing.sources.contains(&source) {
                existing.sources.push(source);
            }
            // `project_dir` stays as first seen: a user-level server does
            // not become project-bound because one project repeats it.
            return;
        }
        found.push(Discovered {
            name: name.to_string(),
            alias: String::new(),
            definition,
            sources: vec![source],
            project_dir: dir.map(Path::to_path_buf),
        });
    };

    let home = &roots.home;
    let cwd = &roots.cwd;

    // Claude Code: user scope, then each project's local scope.
    let claude = home.join(".claude.json");
    if let Some(doc) = read_json(&claude) {
        let source = |project: Option<&str>| Source {
            client: "claude-code",
            path: claude.display().to_string(),
            project: project.map(str::to_string),
        };
        for (name, def) in entries(doc.get("mcpServers")) {
            add(&name, def, source(None), None);
        }
        if let Some(projects) = doc.get("projects").and_then(Value::as_object) {
            for (project, body) in projects {
                for (name, def) in entries(body.get("mcpServers")) {
                    add(&name, def, source(Some(project)), Some(Path::new(project)));
                }
            }
        }
    }
    // Every other file is one flat table. Project-local files carry the
    // directory their servers are started from.
    let desktop = "claude_desktop_config.json";
    let files: [(&'static str, PathBuf, &str, Option<&Path>); 7] = [
        (
            "claude-code",
            cwd.join(".mcp.json"),
            "mcpServers",
            Some(cwd),
        ),
        (
            "claude-desktop",
            home.join("Library/Application Support/Claude")
                .join(desktop),
            "mcpServers",
            None,
        ),
        (
            "claude-desktop",
            home.join(".config/Claude").join(desktop),
            "mcpServers",
            None,
        ),
        ("cursor", home.join(".cursor/mcp.json"), "mcpServers", None),
        (
            "cursor",
            cwd.join(".cursor/mcp.json"),
            "mcpServers",
            Some(cwd),
        ),
        (
            "codex",
            home.join(".codex/config.toml"),
            "mcp_servers",
            None,
        ),
        ("vscode", cwd.join(".vscode/mcp.json"), "servers", Some(cwd)),
    ];
    for (client, path, key, dir) in &files {
        let doc = if path.extension().is_some_and(|e| e == "toml") {
            read_toml(path)
        } else {
            read_json(path)
        };
        let Some(doc) = doc else { continue };
        for (name, def) in entries(doc.get(*key)) {
            let source = Source {
                client,
                path: path.display().to_string(),
                project: None,
            };
            add(&name, def, source, *dir);
        }
    }

    // Aliases last, in list order, so the first definition of a name keeps
    // the plain alias and later different ones get `-2`, `-3`.
    let mut taken: Vec<String> = Vec::with_capacity(found.len());
    for d in &mut found {
        d.alias = unique_alias(&sanitize_alias(&d.name), &taken);
        taken.push(d.alias.clone());
    }
    found
}

fn read_text(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                debug!(path = %path.display(), error = %e, "discover: unreadable, skipped");
            }
            None
        }
    }
}

fn read_json(path: &Path) -> Option<Value> {
    let text = read_text(path)?;
    // The parse error could quote file content (a key, say): log its position only.
    serde_json::from_str(&text)
        .map_err(|e| {
            debug!(path = %path.display(), line = e.line(), column = e.column(), "discover: malformed JSON, skipped")
        })
        .ok()
}

fn read_toml(path: &Path) -> Option<Value> {
    let text = read_text(path)?;
    toml::from_str::<Value>(&text)
        .map_err(|_| debug!(path = %path.display(), "discover: malformed TOML, skipped"))
        .ok()
}

/// The `{name: definition}` table under one key, entries that are not a
/// recognizable server dropped.
fn entries(table: Option<&Value>) -> Vec<(String, Definition)> {
    let Some(table) = table.and_then(Value::as_object) else {
        return Vec::new();
    };
    table
        .iter()
        .filter_map(|(name, v)| Some((name.clone(), parse_definition(v)?)))
        .collect()
}

/// Every client uses the same field names: `command`/`args`/`env`/`cwd` for
/// stdio, `url` for http (`type` is ignored; the fields say the same).
fn parse_definition(v: &Value) -> Option<Definition> {
    let obj = v.as_object()?;
    let text = |key: &str| {
        obj.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    if let Some(command) = text("command") {
        let args = obj
            .get("args")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(scalar).collect())
            .unwrap_or_default();
        let env = obj
            .get("env")
            .and_then(Value::as_object)
            .map(|e| {
                e.iter()
                    .filter_map(|(k, v)| Some((k.clone(), scalar(v)?)))
                    .collect()
            })
            .unwrap_or_default();
        return Some(Definition::Stdio {
            command: command.to_string(),
            args,
            env,
            cwd: text("cwd").map(PathBuf::from),
        });
    }
    text("url").map(|url| Definition::Http {
        url: url.to_string(),
    })
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_sanitizing() {
        assert_eq!(sanitize_alias("GitHub"), "github");
        assert_eq!(sanitize_alias("My Server_v2.1"), "my-server-v2-1");
        assert_eq!(sanitize_alias("--x--"), "x");
        assert_eq!(sanitize_alias("日本"), "server");
        let long = sanitize_alias(&"Ab_".repeat(20));
        assert!(config::is_valid_alias(&long), "{long}");
        assert!(long.len() <= 32);
    }

    #[test]
    fn alias_collisions_count_up_and_stay_valid() {
        let taken = vec!["fs".to_string(), "fs-2".to_string()];
        assert_eq!(unique_alias("fs", &taken), "fs-3");
        assert_eq!(unique_alias("db", &taken), "db");
        let long = "a".repeat(32);
        let next = unique_alias(&long, std::slice::from_ref(&long));
        assert_eq!(next, format!("{}-2", "a".repeat(30)));
        assert!(config::is_valid_alias(&next));
    }

    #[test]
    fn selection_parsing() {
        assert_eq!(parse_selection("", 3).unwrap(), Vec::<usize>::new());
        assert_eq!(parse_selection(" none ", 3).unwrap(), Vec::<usize>::new());
        assert_eq!(parse_selection("all", 3).unwrap(), [0, 1, 2]);
        assert_eq!(parse_selection("3, 1 1", 3).unwrap(), [2, 0]);
        assert!(parse_selection("0", 3).is_err());
        assert!(parse_selection("4", 3).is_err());
        assert!(parse_selection("x", 3).is_err());
    }

    #[test]
    fn debug_never_shows_env_values() {
        let def = Definition::Stdio {
            command: "srv".into(),
            args: vec![],
            env: BTreeMap::from([("API_KEY".to_string(), "sk-secret".to_string())]),
            cwd: None,
        };
        let shown = format!("{def:?}");
        assert!(shown.contains("API_KEY"));
        assert!(!shown.contains("sk-secret"));
    }
}
