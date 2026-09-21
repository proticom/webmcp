//! Discovery against fixture files for every supported client, in temp
//! directories standing in for the home directory and the project. The real
//! home is never read.

use std::path::Path;

use serde_json::{json, Value};
use webmcp_daemon::config::{is_valid_alias, Config};
use webmcp_daemon::discover::{self, Definition, Discovered, Roots, REMOTE_NOT_ATTACHABLE};
use webmcp_daemon::output::{self, DiscoverReport};
use webmcp_daemon::proto::{SessionMode, Transport};

const SECRETS: [&str; 5] = [
    "ghp_SECRET_github",
    "sk-SECRET-desktop",
    "SECRET_cursor_value",
    "SECRET_codex_value",
    "SECRET_vscode_value",
];

struct Fixture {
    _home: tempfile::TempDir,
    _cwd: tempfile::TempDir,
    roots: Roots,
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn empty() -> Fixture {
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let roots = Roots {
        home: home.path().to_path_buf(),
        cwd: cwd.path().to_path_buf(),
    };
    Fixture {
        _home: home,
        _cwd: cwd,
        roots,
    }
}

/// One fixture per file format, with overlaps to exercise de-duplication
/// and alias collisions.
fn full() -> Fixture {
    let fx = empty();
    let (home, cwd) = (&fx.roots.home, &fx.roots.cwd);
    let github = json!({
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-github"],
        "env": {"GITHUB_TOKEN": SECRETS[0]}
    });

    // Claude Code: user scope and one project scope.
    write(
        &home.join(".claude.json"),
        &json!({
            "numStartups": 12,
            "mcpServers": {
                "GitHub": github,
                "linear": {"type": "http", "url": "https://mcp.linear.app/mcp"}
            },
            "projects": {
                cwd.display().to_string(): {
                    "mcpServers": {"notes": {"command": "./bin/notes-mcp", "args": ["--db", "my notes.db"]}}
                },
                "/somewhere/else": {"mcpServers": {}}
            }
        })
        .to_string(),
    );
    // Claude Code project file: the same GitHub definition again.
    write(
        &cwd.join(".mcp.json"),
        &json!({"mcpServers": {"GitHub": github}}).to_string(),
    );
    // Claude Desktop, macOS and Linux locations.
    write(
        &home.join("Library/Application Support/Claude/claude_desktop_config.json"),
        &json!({"mcpServers": {
            "GitHub": github,
            "files": {"command": "uvx", "args": ["mcp-files"], "env": {"OPENAI_API_KEY": SECRETS[1], "PORT": 8080}}
        }})
        .to_string(),
    );
    write(
        &home.join(".config/Claude/claude_desktop_config.json"),
        &json!({"mcpServers": {"local-web": {"url": "http://127.0.0.1:3000/mcp"}}}).to_string(),
    );
    // Cursor, user and project. `github` differs from Claude's `GitHub`
    // in definition but sanitizes to the same alias.
    write(
        &home.join(".cursor/mcp.json"),
        &json!({"mcpServers": {
            "github": {"command": "docker", "args": ["run", "-i", "ghcr.io/github/github-mcp-server"],
                       "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": SECRETS[2]}}
        }})
        .to_string(),
    );
    write(
        &cwd.join(".cursor/mcp.json"),
        &json!({"mcpServers": {"My Tool_v2": {"command": "node", "args": ["server.js"]}}})
            .to_string(),
    );
    // Codex CLI.
    write(
        &home.join(".codex/config.toml"),
        &format!(
            r#"model = "gpt-5"

[mcp_servers.docs]
command = "docs-mcp"
args = ["--stdio"]

[mcp_servers.docs.env]
DOCS_API_KEY = "{}"

[mcp_servers.remote]
url = "https://example.com/mcp"
"#,
            SECRETS[3]
        ),
    );
    // VS Code.
    write(
        &cwd.join(".vscode/mcp.json"),
        &json!({"servers": {
            "pg": {"type": "stdio", "command": "pg-mcp", "env": {"PGPASSWORD": SECRETS[4]}},
            "junk": "not an object",
            "empty": {}
        }})
        .to_string(),
    );
    fx
}

fn by_alias<'a>(found: &'a [Discovered], alias: &str) -> &'a Discovered {
    found
        .iter()
        .find(|d| d.alias == alias)
        .unwrap_or_else(|| panic!("no `{alias}` in {found:?}"))
}

#[test]
fn every_format_is_read_and_normalized() {
    let fx = full();
    let found = discover::discover(&fx.roots);
    let aliases: Vec<&str> = found.iter().map(|d| d.alias.as_str()).collect();
    assert_eq!(
        aliases,
        [
            "github",     // ~/.claude.json
            "linear",     // ~/.claude.json, remote
            "notes",      // ~/.claude.json projects.<cwd>
            "files",      // Claude Desktop (macOS path)
            "local-web",  // Claude Desktop (Linux path)
            "github-2",   // ~/.cursor/mcp.json, a different definition
            "my-tool-v2", // ./.cursor/mcp.json
            "docs",       // ~/.codex/config.toml
            "remote",     // ~/.codex/config.toml, remote
            "pg",         // ./.vscode/mcp.json
        ]
    );
    assert!(found.iter().all(|d| is_valid_alias(&d.alias)));

    let files = by_alias(&found, "files");
    assert_eq!(files.target(), "uvx mcp-files");
    // Non-string scalars in env are kept as text.
    assert_eq!(files.env_names(), ["OPENAI_API_KEY", "PORT"]);

    let docs = by_alias(&found, "docs");
    assert_eq!(docs.sources[0].client, "codex");
    assert_eq!(docs.target(), "docs-mcp --stdio");
    assert_eq!(docs.env_names(), ["DOCS_API_KEY"]);

    let pg = by_alias(&found, "pg");
    assert_eq!(pg.sources[0].client, "vscode");
    assert_eq!(pg.effective_cwd(), Some(fx.roots.cwd.as_path()));

    // A project-scoped Claude Code server runs from its project directory,
    // and arguments with spaces survive as one argument.
    let notes = by_alias(&found, "notes");
    assert_eq!(
        notes.sources[0].project.as_deref(),
        Some(&*fx.roots.cwd.display().to_string())
    );
    let entry = notes.to_entry("notes", SessionMode::PerSession).unwrap();
    assert_eq!(entry.cwd.as_deref(), Some(fx.roots.cwd.as_path()));
    assert_eq!(
        entry.argv().unwrap(),
        ["./bin/notes-mcp", "--db", "my notes.db"]
    );
}

#[test]
fn identical_definitions_are_merged_and_keep_every_source() {
    let fx = full();
    let found = discover::discover(&fx.roots);
    let github = by_alias(&found, "github");
    assert_eq!(github.name, "GitHub");
    let clients: Vec<&str> = github.sources.iter().map(|s| s.client).collect();
    assert_eq!(clients, ["claude-code", "claude-code", "claude-desktop"]);
    assert!(github.sources[0].path.ends_with(".claude.json"));
    assert!(github.sources[1].path.ends_with(".mcp.json"));
    assert_eq!(found.iter().filter(|d| d.name == "GitHub").count(), 1);

    // Same alias after sanitizing, different definition: kept apart.
    let other = by_alias(&found, "github-2");
    assert_eq!(other.name, "github");
    assert!(matches!(&other.definition, Definition::Stdio { command, .. } if command == "docker"));
}

#[test]
fn remote_urls_are_listed_but_not_attachable() {
    let fx = full();
    let found = discover::discover(&fx.roots);
    for alias in ["linear", "remote"] {
        let d = by_alias(&found, alias);
        assert!(!d.attachable());
        assert_eq!(d.not_attachable(), Some(REMOTE_NOT_ATTACHABLE));
        assert!(d.to_entry(alias, SessionMode::PerSession).is_err());
        let e = discover::resolve(&found, alias).unwrap_err();
        assert!(e.to_string().contains(REMOTE_NOT_ATTACHABLE), "{e}");
    }
    let local = by_alias(&found, "local-web");
    assert!(local.attachable());
    let entry = local.to_entry("local-web", SessionMode::Shared).unwrap();
    assert_eq!(entry.transport, Transport::Http);
    assert_eq!(entry.url.as_deref(), Some("http://127.0.0.1:3000/mcp"));
}

#[test]
fn env_values_never_appear_in_any_output() {
    let fx = full();
    let found = discover::discover(&fx.roots);
    let json = output::line(&DiscoverReport::new(&found));
    let debug = format!("{found:?}");
    for secret in SECRETS {
        assert!(!json.contains(secret), "JSON leaks {secret}");
        assert!(!debug.contains(secret), "Debug leaks {secret}");
    }
    // The names are there, which is the point.
    for name in [
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "DOCS_API_KEY",
        "PGPASSWORD",
    ] {
        assert!(json.contains(name), "{name}");
    }
}

#[test]
fn attaching_carries_env_values_into_the_config() {
    let fx = full();
    let found = discover::discover(&fx.roots);
    let github = discover::resolve(&found, "GitHub").unwrap();
    assert_eq!(github.alias, "github");
    let entry = github
        .to_entry(&github.alias, SessionMode::PerSession)
        .unwrap();
    assert_eq!(entry.transport, Transport::Stdio);
    assert_eq!(
        entry.command.as_deref(),
        Some("npx -y @modelcontextprotocol/server-github")
    );
    assert_eq!(entry.env["GITHUB_TOKEN"], SECRETS[0]);

    // And it survives the config file, which is where the daemon reads it.
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = Config {
        device_id: "dev_1".into(),
        handle: "alice".into(),
        device_name: "studio".into(),
        org_id: None,
        base_url: "https://webmcp.fast".into(),
        relay_url: "wss://webmcp.fast/connect".into(),
        hardware_id: "00".into(),
        servers: vec![],
    };
    cfg.attach(entry).unwrap();
    cfg.save_to(dir.path()).unwrap();
    let back = Config::load_from(dir.path()).unwrap();
    assert_eq!(back.servers[0].env["GITHUB_TOKEN"], SECRETS[0]);
}

#[test]
fn resolve_by_name_or_alias() {
    let fx = full();
    let found = discover::discover(&fx.roots);
    // Exact alias wins over name: `github` is Claude's entry, not Cursor's.
    assert_eq!(discover::resolve(&found, "github").unwrap().name, "GitHub");
    assert_eq!(
        discover::resolve(&found, "github-2").unwrap().name,
        "github"
    );
    assert_eq!(
        discover::resolve(&found, "My Tool_v2").unwrap().alias,
        "my-tool-v2"
    );
    let e = discover::resolve(&found, "nope").unwrap_err();
    assert!(e.to_string().contains("webmcp discover"), "{e}");
}

#[test]
fn missing_and_malformed_files_are_tolerated() {
    // Nothing at all.
    assert!(discover::discover(&empty().roots).is_empty());

    let fx = empty();
    let (home, cwd) = (&fx.roots.home, &fx.roots.cwd);
    write(&home.join(".claude.json"), "{ this is not json");
    write(
        &home.join(".codex/config.toml"),
        "[mcp_servers.x\ncommand = ",
    );
    write(&home.join(".cursor/mcp.json"), "[]");
    write(&cwd.join(".mcp.json"), r#"{"mcpServers": "nope"}"#);
    write(
        &cwd.join(".vscode/mcp.json"),
        r#"{"servers": {"ok": {"command": "srv"}, "bad": {"command": 5}, "blank": {"command": "  "}}}"#,
    );
    // A directory where a file is expected.
    std::fs::create_dir_all(cwd.join(".cursor/mcp.json")).unwrap();

    let found = discover::discover(&fx.roots);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].alias, "ok");
}

#[test]
fn discover_json_shape() {
    let fx = full();
    let found = discover::discover(&fx.roots);
    let line = output::line(&DiscoverReport::new(&found));
    assert!(!line.contains('\n'));
    let doc: Value = serde_json::from_str(&line).unwrap();
    let servers = doc["servers"].as_array().unwrap();
    assert_eq!(servers.len(), found.len());
    assert_eq!(doc.as_object().unwrap().len(), 1, "one top-level key");

    let claude = fx.roots.home.join(".claude.json").display().to_string();
    let project = fx.roots.cwd.join(".mcp.json").display().to_string();
    let desktop = fx
        .roots
        .home
        .join("Library/Application Support/Claude/claude_desktop_config.json")
        .display()
        .to_string();
    assert_eq!(
        servers[0],
        json!({
            "name": "GitHub",
            "alias": "github",
            "kind": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": ["GITHUB_TOKEN"],
            "attachable": true,
            "sources": [
                {"client": "claude-code", "path": claude},
                {"client": "claude-code", "path": project},
                {"client": "claude-desktop", "path": desktop}
            ]
        })
    );
    assert_eq!(
        servers[1],
        json!({
            "name": "linear",
            "alias": "linear",
            "kind": "http",
            "url": "https://mcp.linear.app/mcp",
            "attachable": false,
            "reason": "remote, not attachable",
            "sources": [{"client": "claude-code", "path": claude}]
        })
    );
}
