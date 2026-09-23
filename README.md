# webmcp

The open-source daemon for [webmcp.fast](https://webmcp.fast): any local MCP
server, reachable by any agent harness. `webmcp` pairs your machine, holds one
outbound connection to the gateway (no inbound ports, no tunnel), and exposes
each local MCP server you attach at its own authenticated URL:
`https://<handle>.webmcp.fast/<device>/<server>/mcp`.

The daemon is the part that runs on your machine, so it is open (Apache-2.0).
The hosted gateway is not in this repository. Wire protocol: `docs/PROTOCOL.md`;
what the daemon can and cannot be made to do: `THREAT_MODEL.md`.

## Install

With Node 18+ (macOS Apple silicon or Intel, Linux x86_64 or arm64, Windows x64):

    npm i -g @proticom/webmcp
    webmcp up

or, without installing, `npx @proticom/webmcp up`. The npm package is a small
launcher with no runtime dependencies and no install script; the prebuilt
binary comes from a platform package (`@proticom/webmcp-darwin-arm64` and so
on) picked by npm. Every package is published from GitHub Actions with a
provenance attestation: `npm audit signatures` verifies that what you
installed was built by the release workflow in this repository.

Linux, without Node: the GitHub release has one tarball and SHA-256 checksum
per target ([releases](https://github.com/proticom/webmcp/releases)), and
`scripts/install.sh` downloads, verifies and copies one binary to `~/.local/bin`:

    curl -fsSL https://webmcp.fast/install.sh | sh

Read it first. On macOS the script points you at npm instead, because the
tarballs are not code-signed (there is no Apple Developer ID) and Gatekeeper
blocks a downloaded unsigned binary; `WEBMCP_ALLOW_UNSIGNED=1` overrides.
Windows gets a `.zip` on the release page. Or build from source (Rust 1.94+):

    cargo install --git https://github.com/proticom/webmcp --locked
    webmcp --version

## Quick start: `webmcp up`

    webmcp up

One command, safe to run again at any point. It does only what is still missing:

1. **Pairs** this machine. It prints a link (and tries to open it in your browser): sign in with the
   emailed code, which creates the account if you have none, pick a handle, approve the device. The
   login code never passes through the daemon. `--name laptop`, `--base-url URL`, `--no-browser`;
   `--force` pairs again after a revoke (attached servers are kept).
2. **Offers the MCP servers this machine already has**, found read-only in the configs of Claude Code
   (`~/.claude.json`, `./.mcp.json`), Claude Desktop, Cursor (`~/.cursor/mcp.json`, `./.cursor/mcp.json`),
   Codex CLI (`~/.codex/config.toml`) and VS Code (`./.vscode/mcp.json`). At a terminal you pick by
   number; `--attach <name>` (repeatable) attaches without asking; `--no-attach` skips. Nothing is ever
   attached without one of those. Attaching a stdio server **copies its env variables, values included,
   into the webmcp config** (that is how the server gets its API keys); the output names the variables,
   never the values. Remote-URL entries are listed as "remote, not attachable". `webmcp discover`
   shows the list on its own.
3. **Background service** (macOS, Linux): asks at a terminal, `--service` installs without asking;
   otherwise it says how. Elsewhere run `webmcp connect` under your own supervisor.
4. **Reports** each server's URL, `https://<handle>.webmcp.fast/<device>/<alias>/mcp`. Paste it into
   Claude, ChatGPT or Grok as a custom connector, sign in, click Allow.

### For agents: `--json`

    webmcp up --json --attach github --service

`--json` (global; honoured by `up`, `discover`, `status`, `servers`, `attach`, `detach`,
`service status`) prints exactly one JSON object on stdout, on one line; progress and logs go to
stderr, and nothing ever prompts. `up` is the one two-line case: if it has to pair it first prints

    {"event":"approval_required","verification_uri_complete":"https://webmcp.fast/activate?code=ABCD-EFGH","user_code":"ABCD-EFGH","expires_in":900}

(show that link to the human and keep the process running), and always ends with

    {"event":"ready","handle":"alice","device":"studio","servers":[{"alias":"github","url":"https://alice.webmcp.fast/studio/github/mcp","env_carried":["GITHUB_TOKEN"]}],"service":"installed","next":"…"}

`service` is `installed`, `skipped` or `unsupported`; `env_carried` (names only) appears on servers this
run attached. On failure `event` is `error` with `code` (`access_denied`, `expired_token`, `device_limit`,
`device_name_taken`, `hardware_already_paired`, `rate_limited`, `invalid_request`, `network`, or `error`)
and `message`; `handle`/`device` are null if it failed before pairing. Any other command fails as
`{"event":"error","code":"error","message":"…"}`. Exit codes: `0` ok, `1` error, `2` approval declined,
`3` approval expired. `webmcp discover --json` gives
`{"servers":[{"name","alias","kind":"stdio"|"http","command","args","env":[names],"cwd","url","attachable","reason","sources":[{"client","path","project"}]}]}`
(absent fields omitted); pass an entry's `alias` or `name` to `up --attach`.

## Manual commands

    webmcp login --code ABCD-EFGH [--name laptop] [--base-url https://webmcp.fast]   # pair with a dashboard code
    webmcp connect [--once]                # keep the relay open; --once = handshake + one ping/pong
    webmcp status                          # config path, handle, device id, key fingerprint
    webmcp discover                        # MCP servers found in other tools' configs (read-only)
    webmcp attach fs [--env KEY=VAL]... [--cwd DIR] [--mode per-session|exclusive] [--max-sessions N] \
        -- npx -y @modelcontextprotocol/server-filesystem /tmp
    webmcp attach gnosys --stdio "npx -y @acme/gnosys"     # same, command as one quoted string
    webmcp attach web --http http://localhost:3000/mcp --mode shared
    webmcp servers / webmcp detach <alias>

Only one `webmcp connect` runs per device: it holds a lock (`daemon.lock` in the config directory) and a
second one exits naming the first one's pid. If another machine connects with a copy of this identity,
the gateway closes this connection with `1012 "replaced"` and the daemon stops instead of fighting for
the socket (under the background service it exits cleanly, so launchd does not restart it).

Config lives in `~/.config/webmcp/` (`$XDG_CONFIG_HOME`, or `~/Library/Application Support/webmcp/`
on macOS; override with `WEBMCP_CONFIG_DIR`): `config.toml` plus the Ed25519 seed in `device.key` (0600).
Logs go to stderr; set `RUST_LOG=debug` for frame-level detail. `webmcp connect` serves the
attached servers: a stdio server is spawned once per MCP session (`exclusive`: one session at a time) and
killed when the session closes, idles for 30 min or the relay connection drops; an `--http` server is
reached as an MCP Streamable HTTP client. `--mode shared` over stdio is not supported yet.

`attach` and `detach` take effect on a running `webmcp connect` within a couple of seconds, no restart:
it polls `config.toml` and re-advertises the server list. Sessions on a detached alias end with
`detached`, sessions on an alias whose definition changed end with `reconfigured` (the next session uses
the new one), everything else keeps running. A config that does not parse is ignored until it does.
Only `servers` is reloaded; after `webmcp login --force`, restart `webmcp connect`.

## Running in the background (macOS, Linux)

```
webmcp service install     # start at login, restart if it stops
webmcp service status
webmcp service uninstall   # pairing and attached servers are kept
```

On macOS this writes a per-user LaunchAgent (`~/Library/LaunchAgents/fast.webmcp.daemon.plist`,
no sudo) that runs `webmcp connect`; logs go to `~/Library/Logs/webmcp/daemon.log`.
On Linux it writes a systemd user unit (`~/.config/systemd/user/webmcp.service`,
`Restart=on-failure`, no sudo) and runs `systemctl --user daemon-reload && enable
&& restart`; logs go to `~/.local/state/webmcp/daemon.log` (and `journalctl --user -u webmcp`).
A user unit only runs while you have a session; `loginctl enable-linger $USER`
keeps it up after logout and across reboots. Both record your shell's `PATH` at
install time, because stdio servers are usually launched through `npx`, `uvx` or a
`#!/usr/bin/env node` shim that the supervisor's minimal `PATH` would not find: run
`install` again after upgrading `webmcp` or changing your `PATH`. If the gateway
says the device must be paired again, the service exits cleanly instead of looping
(neither supervisor restarts a clean exit); `webmcp up --force --service`.
Windows: the binary runs (`webmcp connect` in a terminal or under your own
supervisor), but `webmcp service` is not available there yet.

