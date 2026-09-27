# Threat model

What this daemon is: a program you run as yourself that holds one outbound
WebSocket to `webmcp.fast` and, on request, starts or forwards to the local MCP
servers **you** attached. It opens no listening port.

## What it trusts

| Thing | Why | Limit |
|---|---|---|
| Your config file | Only you (and programs running as you) can write it. It is the single place a server can be added. | `device.key` and `config.toml` are written `0600` in your user config directory. |
| The gateway it paired with | It authenticates the daemon with a signed challenge (Ed25519; the private key never leaves the machine). | The gateway can ask the daemon to open sessions on attached servers, end sessions, and **detach** a server. It cannot ask it to attach or run anything else: the protocol has no such frame. |

## What a malicious or compromised gateway could do

- Send arbitrary MCP messages to the servers you attached, as if an approved
  agent had. It cannot reach a server you did not attach.
- Put the id of an agent credential you approved on sessions of its own,
  which gets past `webmcp approvals` (see the next section).
- Detach servers or drop your connection (denial of service).

It could **not**: run a command of its choosing, read files outside what an
attached server itself exposes, add a server, turn off local approval of new
agents, or obtain your private key.

So: attach only servers whose full tool surface you would be comfortable
exposing to the agents you approve. An attached filesystem server rooted at `/`
exposes `/`.

## What a stolen webmcp.fast account could do

Whoever signs in as you can connect a new agent, by OAuth consent or a
connector token, to every server you enabled. `webmcp approvals on` stops that
at the machine: a credential this machine has not approved opens no session,
whatever the gateway says. The attempt is recorded in `agents.json` and
announced by a desktop notification. The setting and the approved list live in
`config.toml`, and no frame reads or changes them, so only `webmcp approvals
off` on the machine turns the check off. It also catches a gateway-side
authorization bug that mints a credential.

The limit: the daemon checks the credential id the gateway reports on each
`session_open`. A fully compromised gateway can report an approved id on
sessions of its own, so approvals do not protect against the gateway itself.

The name shown for a waiting agent comes from the gateway, and whoever
connected the agent chose it. Approve only an agent you just connected
yourself. Names lose their control characters before they are stored or
printed, and the notification hands its text to `osascript` or `notify-send`
as an argument, never as part of a script.

## What another local program running as you could do

Anything you can, including editing the config to attach a server, approve an
agent or turn approvals off. The optional dashboard preference "ask me before
a newly attached server goes live" exists for this case: with it on, a newly
attached server does nothing until you enable it while signed in.

## Secrets

- Pairing never sends your emailed sign-in code through the daemon. `webmcp up`
  prints a link; you sign in in your own browser.
- `webmcp discover` reads other tools' MCP configs read-only and prints
  environment variable **names**, never values. When you attach a discovered
  server, its environment is copied into webmcp's config so the server still
  gets its keys; the command says which variables were copied. That is why
  `config.toml` is written `0600`.
- Logs never contain tokens, keys or MCP message bodies at the default level.

## Process model

Each agent session gets its own child process by default (`per-session`),
killed when the session ends, idles 30 minutes, when the server is disabled,
removed, detached or redefined, or when the connection drops. A lock file prevents two daemons serving one device.
