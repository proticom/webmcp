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

## 1b. Adding a passkey from the device

Once an account has a paired device, its first passkey, and any passkey added
without an existing one (recovery), must be started from that device. The
daemon proves it holds the device key (`webmcp passkey`) with a signed request
(§1c):

```
POST https://webmcp.fast/api/v1/device/passkey-link
Content-Type: application/json
Content-Digest: sha-256=:…:
Signature-Input: webmcp=("@method" "@authority" "@path" "@query" "content-digest");created=…;nonce="…";alg="ed25519";keyid="dev_…";tag="webmcp-device"
Signature: webmcp=:…:
User-Agent: webmcp-daemon/<version> (<platform>)

{}
```

| Status | Body | Meaning |
|---|---|---|
| 201 | `{"url":"https://…","expires_in":600}` | Open `url` in a browser within `expires_in` seconds. |
| 400 | `{"error":"bad_digest"}` / `{"error":"bad_nonce"}` | The body does not match `Content-Digest`, or the nonce is missing or too short. |
| 401 | `{"error":"bad_signature"}` / `{"error":"replayed"}` | The signature does not verify, is outside the time window, or its nonce was already used. |
| 404 | `{"error":"unknown_device"}` | Unknown or revoked device. |
| 429 | `{"error":"rate_limited"}` | Too many links asked for. |

Every error body may carry a `message`. The daemon reports the `error` code
whatever the status, and treats a `429` without a JSON body as
`rate_limited`.

The link works once, for 10 minutes, and only for a signed-in user who can
manage that device's handle. It lets that browser add a passkey without an
existing one. The daemon only opens a link on the site it is paired with.

## 1c. Signed device requests

A device proves it holds its key with HTTP Message Signatures (RFC 9421),
Ed25519, and for requests with a body a `Content-Digest` (RFC 9530,
`sha-256`). The signature is labelled `webmcp` and:

- covers `"@method" "@authority" "@path" "@query"`, plus `"content-digest"`
  when there is a body;
- carries `created` (Unix seconds), `keyid` (the device id), `alg="ed25519"`,
  a random `nonce` of 16 to 128 characters, and `tag="webmcp-device"`.

The gateway accepts a signature created within 300 s of its own clock, either
way, and each nonce once per device. For a WebSocket upgrade the signed
authority, path and query are those of the `wss` URL, which the gateway sees
as the same `https` request.

Daemons up to 0.2.1 used two older, non-standard signatures instead (a
signed `ts` in the passkey-link body, and an in-band `challenge`/`auth` on
the relay socket). The gateway still accepts them while those daemons are in
use; they will be removed.

## 2. Relay connection

```
GET wss://webmcp.fast/connect?device_id=dev_…
Signature-Input: webmcp=("@method" "@authority" "@path" "@query");created=…;nonce="…";alg="ed25519";keyid="dev_…";tag="webmcp-device"
Signature: webmcp=:…:
User-Agent: webmcp-daemon/<version> (<platform>)
```

The upgrade is signed (§1c), so the gateway checks the device before any
socket exists. It answers `401` to a signature that does not verify, and
`404` if the device is unknown or revoked. The daemon treats `404` as final:
it stops and tells the user to pair again (`webmcp up --force`) instead of
reconnecting. After the upgrade:

```
daemon → {"t":"hello","v":1,"device_id":"dev_…","daemon_version":"0.3.0","platform":"macos-aarch64"}
gateway → {"t":"welcome","handle":"alice","device":"macbook","server_time":"2026-09-19T21:00:00Z"}
```

A `hello` whose `device_id` differs from the signed `keyid` closes with
`4401`. Any other frame before `welcome` closes with `4400`. A `hello` with
`v` other than 1 closes with `4406`.

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
| `{"t":"servers","servers":[{"alias":"gnosys","transport":"stdio"\|"http","mode":"per-session"\|"shared"\|"exclusive","status":"ready"\|"error","error":"…"?}],"require_approval":true?}` | daemon → gateway | Sent on connect and again whenever the attached set or the device's approvals change. A repeat with nothing new in it is harmless. The gateway keeps only the first 200 entries. `require_approval` is sent only as `true`, while the device approves new agents itself (see *Local approval of new agents*). Absent means `false`. |
| `{"t":"error","code":"…","message":"…"?}` | either | Non-fatal unless followed by close. |

MCP relay (the daemon must still ignore unknown `t` values):

| Frame | Direction | Purpose |
|---|---|---|
| `{"t":"session_open","sid":"ses_…","server":"gnosys","client":{"name":"…","version":"…"},"credential":{"id":"grt_…","kind":"oauth"\|"token","name":"…"}?}` | gateway → daemon | An agent harness sent `initialize` to `/<device>/<server>/mcp`. `client` is its `clientInfo`, truncated. `credential` is the credential the request carried: an OAuth grant (`oauth`, `name` is the agent's name) or a connector token (`token`, `name` is its label). Its `id` stays the same for the life of the credential, for example `grt_…` or `ctk_…`. Older gateways omit `credential`. |
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
`unknown_session` (an `mcp` frame for a `sid` it does not hold, which can
cross with its own close; the gateway ignores closes for sessions it no
longer tracks), and `approval_required` (the device approves new agents
itself and this credential is not approved there, or `session_open` carried
no `credential`). After a config reload: `detached` (alias removed),
`reconfigured` (its definition changed) or `approval_required` (its
credential is no longer approved, or approvals were just turned on). From the gateway: `client_closed`
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

### Tool permissions on the device

Each attached server can carry a tool rule and a confirmation setting in the
device's config (`webmcp tools`, `webmcp confirm`). No frame reads or changes
them. The daemon applies them to every session, whatever the gateway sends:

- `tools/list` answers lose the tools the rule does not allow.
- A `tools/call` for such a tool is answered by the daemon with a JSON-RPC
  error (`-32001`) and never reaches the server.
- With confirmation on, a `tools/call` waits for the owner's Allow on the
  device; Deny or no answer within 60 s gets the same error.
- A batch (a JSON array) gets `-32600`. A request with no id that is not a
  `notifications/*` message is dropped.

The gateway's own per-tool policy can narrow this further, never widen it.

### Local approval of new agents

The owner can make a device approve new agents itself (`webmcp approvals
on`). The setting and the list of approved credential ids live only in the
device's config. No frame reads or changes either, so the gateway cannot turn
it off. While it is on:

- A `session_open` whose `credential.id` is not approved on the device, or
  that carries no `credential`, gets `session_close` with reason
  `approval_required`. No backend starts for it.
- When an approval is withdrawn, or approvals are turned on, every live
  session whose credential is not approved ends with `approval_required`.
- The `servers` frame carries `"require_approval":true`.

The owner approves a waiting credential on the device (`webmcp approve`), and
its next `session_open` succeeds. On `approval_required` the gateway should
tell the agent's owner to run `webmcp approve` on that device. It cannot
approve anything itself.
