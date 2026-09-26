# webmcp.fast wire protocol, v1

This is the contract between the daemon and the gateway: **pairing** (HTTP,
once per device) and the **relay connection** (WebSocket, held open by the
daemon). How agents reach an attached server is documented for agent
developers at https://webmcp.fast/docs.

All JSON. Timestamps are RFC 3339 UTC. Binary values are standard base64
(with padding) unless stated otherwise. Frame type is the `t` field.

## 1. Pairing

The user creates a pairing code in the dashboard (`/app/devices`). It is
8 characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, shown as `ABCD-EFGH`,
valid for 10 minutes, single use.

The daemon generates an Ed25519 keypair (private key never leaves the
machine) and a hardware id: `sha256` of a stable machine identifier
(`machine-uid`), hex encoded. A machine with no readable identifier gets a
random 32-byte hex id instead, generated once and kept in the config so that
pairing again sends the same one. It then calls:

```
POST https://webmcp.fast/api/v1/pair
Content-Type: application/json
User-Agent: webmcp-daemon/<version> (<platform>)

{
  "code": "ABCD-EFGH",            // dashes and case are ignored
  "device_name": "macbook",        // see name rules below; unique per handle
  "public_key": "<base64, 32 bytes>",
  "hardware_id": "<hex sha256>",
  "daemon_version": "0.1.0",
  "platform": "macos-aarch64"
}
```

Responses:

| Status | Body | Meaning |
|---|---|---|
| 201 | `{"device_id":"dev_…","handle":"alice","org_id":"org_…","relay_url":"wss://webmcp.fast/connect","base_url":"https://webmcp.fast"}` | Paired. Persist all fields. |
| 400 | `{"error":"invalid_request","message":"…"}` | Malformed body or bad device name. |
| 404 | `{"error":"code_not_found"}` | Unknown, expired or used code. |
| 409 | `{"error":"device_name_taken"}` | Another device on this handle has that name. |
| 409 | `{"error":"device_limit"}` | Plan allows no more devices. |
| 409 | `{"error":"hardware_already_paired"}` | This machine is already paired to another free handle. |
| 429 | `{"error":"rate_limited"}` | Too many attempts from this IP. |

Name rules. A device name is 1-32 characters of `[a-z0-9-]`, starting and
ending with a letter or digit. A handle is 3-32 characters of `[a-z0-9-]`,
starting and ending with a letter or digit, with no two hyphens in a row. A
server alias matches `^[a-z0-9][a-z0-9-]{0,31}$`.

The daemon stores `device_id`, `handle`, `org_id`, `device_name`,
`hardware_id`, `relay_url` and `base_url` in `config.toml` and the key in
`device.key`, both mode `0600`, in its config directory
(`$XDG_CONFIG_HOME/webmcp/` or `~/.config/webmcp/`;
`~/Library/Application Support/webmcp/` on macOS;
`%APPDATA%\webmcp\config` on Windows; `WEBMCP_CONFIG_DIR` overrides).

## 1a. Pairing without the dashboard: device authorization

For `webmcp up`, where an agent or a person at a terminal drives setup. Shaped
after RFC 8628 (`gh auth login`, `tailscale up`). The human's only act is to
open a link, sign in with the emailed code in their own browser (which creates
the account if there is none), accept or choose a handle if they have none,
and approve the device. The login code never passes through the daemon or an
agent.

```
POST https://webmcp.fast/api/v1/device/start
{ "device_name": "studio", "public_key": "<base64, 32 bytes>", "hardware_id": "<hex sha256>",
  "daemon_version": "0.1.0", "platform": "macos-aarch64" }
```

| Status | Body |
|---|---|
| 200 | `{"device_code":"<opaque, 43 chars>","user_code":"ABCD-EFGH","verification_uri":"https://webmcp.fast/activate","verification_uri_complete":"https://webmcp.fast/activate?code=ABCD-EFGH","expires_in":900,"interval":3}` |
| 400 | `{"error":"invalid_request","message":"…"}` (same field rules as §1) |
| 429 | `{"error":"rate_limited"}` |

The daemon shows `verification_uri_complete` (and the code, for a person
typing it on another device), then polls no faster than `interval` seconds:

```
POST https://webmcp.fast/api/v1/device/poll
{ "device_code": "…" }
```

| Status | Body | Meaning |
|---|---|---|
| 200 | the `201` body of §1 plus `"device_name":"studio"` | Approved and paired. Persist it, using this device name: the human may have changed it while approving. The `device_code` is now spent. |
| 400 | `{"error":"authorization_pending"}` | Keep polling. |
| 400 | `{"error":"slow_down"}` | Add 5 s to the interval, keep polling. |
| 400 | `{"error":"access_denied"}` | The human declined. Stop. |
| 400 | `{"error":"expired_token"}` | 15 minutes passed. Stop; start again. |
| 409 | `{"error":"device_name_taken" \| "device_limit" \| "hardware_already_paired"}` | As in §1; decided at approval time. Stop. |
| 429, 5xx, network error | | Treat `429` as `slow_down`. Retry the rest until `expires_in` has passed locally, then give up as expired. |

The key pair is generated before `start`, so approval binds to that public
key: a different machine that learns the `user_code` gains nothing. If the
human chose a different device name on the approval page, the `200` body's
`device_name` is authoritative. Polling starts after one full `interval`.

## 2. Relay connection

```
GET wss://webmcp.fast/connect?device_id=dev_…
User-Agent: webmcp-daemon/<version> (<platform>)
```

The gateway rejects the upgrade with HTTP `404` if the device is unknown or
revoked. The daemon treats that as final: it stops and tells the user to pair
again (`webmcp up --force`) instead of reconnecting. After upgrade, the
handshake is:

```
daemon → {"t":"hello","v":1,"device_id":"dev_…","daemon_version":"0.1.0","platform":"macos-aarch64"}
gateway → {"t":"challenge","nonce":"<base64, 32 bytes>"}
daemon → {"t":"auth","signature":"<base64, 64 bytes>"}
gateway → {"t":"welcome","handle":"alice","device":"macbook","server_time":"2026-09-19T21:00:00Z"}
```

The signature is Ed25519 over the UTF-8 bytes of:

```
"webmcp-connect-v1\n" + device_id + "\n" + nonce
```

where `nonce` is the base64 string exactly as received. On failure the
gateway sends `{"t":"error","code":"unauthorized"}` and closes with code
`4401`. Any frame before `welcome` other than `hello`/`auth` closes with
`4400`. A `hello` with `v` other than 1 closes with `4406`.

### Keep-alive

The daemon sends the **text frame** `ping` every 30 s. The gateway answers
with the text frame `pong` without waking the tenant object. Three missed
pongs mean reconnect. Reconnect uses exponential backoff from 1 s to 60 s
with jitter. Close codes `4401` and `4403` (revoked) mean stop and tell the
user to pair again; do not retry.

The gateway holds one socket per device. When a second connection for the
same device authenticates, it replaces the first, which is closed with code
`1012` and reason `replaced`. The daemon on the replaced connection exits
instead of reconnecting, so two copies never take turns evicting each other.
A `1012` with any other reason is a gateway restart and is retried like any
other drop.

### Frames after `welcome`

Implemented now:

| Frame | Direction | Purpose |
|---|---|---|
| `{"t":"servers","servers":[{"alias":"gnosys","transport":"stdio"\|"http","mode":"per-session"\|"shared"\|"exclusive","status":"ready"\|"error","error":"…"?}]}` | daemon → gateway | Sent on connect and whenever the attached set changes. The gateway keeps only the first 200 entries. |
| `{"t":"error","code":"…","message":"…"?}` | either | Non-fatal unless followed by close. |

MCP relay (the daemon must still ignore unknown `t` values):

| Frame | Direction | Purpose |
|---|---|---|
| `{"t":"session_open","sid":"ses_…","server":"gnosys","client":{"name":"…","version":"…"}}` | gateway → daemon | An agent harness sent `initialize` to `/<device>/<server>/mcp`. `client` is its `clientInfo`, truncated. |
| `{"t":"session_close","sid":"ses_…","reason":"…"}` | either | Session ended. |
| `{"t":"mcp","sid":"ses_…","msg":{…JSON-RPC…}}` | either | One JSON-RPC message, verbatim, for that session. |
| `{"t":"detach","alias":"gnosys"}` | gateway → daemon | The owner removed this server on the dashboard. The daemon drops the alias from its config, which ends its sessions (`detached`) and produces a fresh `servers` frame. An unknown alias is ignored. There is deliberately no `attach` counterpart. |

Every `sid` maps to exactly one server on this device. The daemon routes by
`sid`, never by inspecting the JSON-RPC body.

`session_open` has no acknowledgement. The gateway sends the `initialize`
request as an `mcp` frame immediately after it, so the daemon queues frames
for a `sid` until its backend is ready. If the session cannot start, the
daemon answers with `session_close`, and the gateway fails the pending
`initialize` with a JSON-RPC error carrying the reason.

`session_close` reasons. From the daemon: `unknown_server`, `busy`
(exclusive server already held), `too_many_sessions` (every session on the
server has a request in flight), `evicted` (the least recently used idle
session on a server at its session cap, closed to admit a new one; its client
gets `404` and initializes again), `unsupported_mode`,
`spawn_failed: <detail>`, `server_exited`, `idle`, `message_too_large`,
`overloaded` (its 256-message session queue filled), `duplicate_session`,
and `unknown_session` (an `mcp` frame for a `sid` it does not hold, which
can cross with its own close; the gateway ignores closes for sessions it no
longer tracks), and after a config reload `detached` (alias removed) or
`reconfigured` (its definition changed). From the gateway: `client_closed`
(HTTP `DELETE`), `token_revoked`, `idle` (24 h without a request), and from
the dashboard `restart`, `server_disabled`, `server_removed`. Neither side replies to a `session_close`.

All sessions on a device end when its socket ends. The daemon stops every
per-session process; the gateway forgets the sessions, and the harness gets
`404` on its next request and initializes again, as the MCP spec prescribes.

The gateway may send `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":…,"reason":…}}`
inside an `mcp` frame when the harness disconnects mid-call or the call
passes the relay ceiling (30 minutes streamed, 5 minutes as a JSON response). It is an ordinary MCP notification and is
passed to the server like any other.

Sizes: an `mcp` frame to the daemon over 1 MiB closes that session; a frame
from the daemon may be up to 8 MiB; the daemon drops the connection on any
WebSocket message over 4 MiB inbound.

### Who decides what is exposed

The daemon's config is the only place a server can be added: `webmcp attach`
and `webmcp detach`, picked up by a running daemon within seconds and
announced with a fresh `servers` frame. The gateway never asks a device to
run anything. It keeps a policy per `(device, alias)` and can only narrow
what the device offers, up to and including asking it to detach a server:

| Policy | Meaning |
|---|---|
| `enabled` | Agents with a credential for it can open sessions. |
| `disabled` | Switched off on the dashboard. Connectors kept. `initialize` gets `403`. |
| `pending` | Offered by the device but not switched on: a new server while the owner's *approve new servers* preference is on, or one held back by the plan limit. `initialize` gets `403`. |
| `removed` | Removed on the dashboard: connectors revoked, sessions ended, `detach` sent (again on every `servers` frame that still lists it, which covers a device that was offline). Hidden from the dashboard. The policy is forgotten once the device stops offering the alias, so attaching it again later starts fresh. |

A server seen for the first time becomes `enabled`, or `pending` if the
preference is on. A policy, once set, survives detach and re-attach. The plan
limit counts enabled servers that are currently advertised, per device.
`{"t":"error","code":"server_limit"}` after a `servers` frame names the
aliases held back by that limit.
