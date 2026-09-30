//! Tool permissions enforced on this machine. The gateway applies the
//! owner's dashboard policy too, but this is the ceiling: whatever the
//! gateway sends, a `tools/call` this machine's config does not allow never
//! reaches the server, and `tools/list` never shows it.
//!
//! Pure message logic, independent of how messages arrive, so the same rules
//! hold for every transport.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// JSON-RPC error codes this module answers with (the gateway's own).
pub const RPC_INVALID_REQUEST: i64 = -32600;
pub const RPC_INVALID_PARAMS: i64 = -32602;
pub const RPC_REFUSED: i64 = -32001;

const TOOL_NAME_MAX: usize = 128;

/// Which tools agents may call on one server.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPolicy {
    /// Every tool the server offers.
    #[default]
    All,
    /// Only tools the server itself marks `readOnlyHint: true`.
    ReadOnly,
    /// Exactly these names.
    Allow(BTreeSet<String>),
}

/// When a call waits for the owner to click Allow on this machine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confirm {
    #[default]
    Never,
    /// Tools that may change things: not marked read-only, and not marked
    /// `destructiveHint: false` (MCP's default for an unmarked tool is
    /// destructive).
    Destructive,
    Always,
}

/// What the server said about one tool in a `tools/list` result.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ToolHints {
    pub read_only: Option<bool>,
    pub destructive: Option<bool>,
}

impl ToolHints {
    /// May change something, by MCP's defaults for missing hints.
    pub fn may_change(self) -> bool {
        self.read_only != Some(true) && self.destructive != Some(false)
    }
}

impl ToolPolicy {
    pub fn allows(&self, name: &str, catalog: &Catalog) -> bool {
        match self {
            ToolPolicy::All => true,
            // A tool the server has not listed yet is refused.
            ToolPolicy::ReadOnly => catalog
                .hints(name)
                .is_some_and(|h| h.read_only == Some(true)),
            ToolPolicy::Allow(names) => names.contains(name),
        }
    }
}

impl Confirm {
    pub fn needed(self, name: &str, catalog: &Catalog) -> bool {
        match self {
            Confirm::Never => false,
            Confirm::Always => true,
            // Unknown tools count as able to change things.
            Confirm::Destructive => catalog.hints(name).unwrap_or_default().may_change(),
        }
    }
}

/// Every tool a session's server has listed so far.
#[derive(Debug, Clone, Default)]
pub struct Catalog(HashMap<String, ToolHints>);

impl Catalog {
    pub fn hints(&self, name: &str) -> Option<ToolHints> {
        self.0.get(name).copied()
    }

    /// Record the `tools` of one `tools/list` result page.
    fn learn(&mut self, result: &Value) {
        let Some(tools) = result.get("tools").and_then(Value::as_array) else {
            return;
        };
        for tool in tools {
            let Some(name) = tool.get("name").and_then(Value::as_str) else {
                continue;
            };
            if name.is_empty() || name.len() > TOOL_NAME_MAX {
                continue;
            }
            let ann = tool.get("annotations");
            let hint = |k: &str| ann.and_then(|a| a.get(k)).and_then(Value::as_bool);
            self.0.insert(
                name.to_string(),
                ToolHints {
                    read_only: hint("readOnlyHint"),
                    destructive: hint("destructiveHint"),
                },
            );
        }
    }
}

/// What to do with one agent → server message.
#[derive(Debug, Clone, PartialEq)]
pub enum Inbound {
    Forward,
    /// Send this reply to the agent instead; the server never sees the message.
    Refuse(Value),
    /// Forward only after the owner allows this call on this machine.
    Confirm {
        tool: String,
    },
    /// Nothing to reply to (an id-less message that is not a notification).
    Drop,
}

/// Per-session policy state: the catalog and which requests were
/// `tools/list`, so their answers can be filtered.
#[derive(Debug, Default)]
pub struct SessionPolicy {
    pub tools: ToolPolicy,
    pub confirm: Confirm,
    catalog: Catalog,
    /// Ids (as JSON text) of `tools/list` requests not yet answered.
    listing: BTreeSet<String>,
}

pub fn rpc_error(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message.into() } })
}

impl SessionPolicy {
    pub fn new(tools: ToolPolicy, confirm: Confirm) -> Self {
        SessionPolicy {
            tools,
            confirm,
            ..SessionPolicy::default()
        }
    }

    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// Judge one message from the agent.
    pub fn inbound(&mut self, msg: &Value) -> Inbound {
        let Some(obj) = msg.as_object() else {
            return Inbound::Refuse(rpc_error(
                Value::Null,
                RPC_INVALID_REQUEST,
                "batching is not supported",
            ));
        };
        let id = obj.get("id").cloned();
        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            // A response to a request the server made (sampling, elicitation).
            return Inbound::Forward;
        };
        let Some(id) = id.filter(|v| !v.is_null()) else {
            // Only notifications may omit the id; anything else could still
            // do work on the server with no reply the policy could refuse.
            return if method.starts_with("notifications/") {
                Inbound::Forward
            } else {
                Inbound::Drop
            };
        };
        match method {
            "tools/list" => {
                self.listing.insert(id.to_string());
                Inbound::Forward
            }
            "tools/call" => {
                let name = obj
                    .get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str)
                    .filter(|n| !n.is_empty() && n.len() <= TOOL_NAME_MAX);
                let Some(name) = name else {
                    return Inbound::Refuse(rpc_error(
                        id,
                        RPC_INVALID_PARAMS,
                        "tools/call needs a tool name of 1 to 128 characters",
                    ));
                };
                if !self.tools.allows(name, &self.catalog) {
                    return Inbound::Refuse(rpc_error(
                        id,
                        RPC_REFUSED,
                        format!(
                            "This machine does not allow the tool \"{name}\". Its owner can allow it with `webmcp tools`."
                        ),
                    ));
                }
                if self.confirm.needed(name, &self.catalog) {
                    return Inbound::Confirm {
                        tool: name.to_string(),
                    };
                }
                Inbound::Forward
            }
            _ => Inbound::Forward,
        }
    }

    /// Filter one message from the server: `tools/list` answers lose the
    /// tools this machine does not allow, after the catalog learns them all.
    pub fn outbound(&mut self, mut msg: Value) -> Value {
        let is_listing = msg.get("method").is_none()
            && msg
                .get("id")
                .is_some_and(|id| self.listing.remove(&id.to_string()));
        if !is_listing {
            return msg;
        }
        let Some(result) = msg.get_mut("result") else {
            return msg;
        };
        self.catalog.learn(result);
        if self.tools == ToolPolicy::All {
            return msg;
        }
        let (tools, catalog) = (&self.tools, &self.catalog);
        if let Some(list) = result.get_mut("tools").and_then(Value::as_array_mut) {
            list.retain(|t| {
                t.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| tools.allows(n, catalog))
            });
        }
        msg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listing() -> Value {
        json!({ "jsonrpc": "2.0", "id": 1, "result": { "tools": [
            { "name": "read_file", "annotations": { "readOnlyHint": true } },
            { "name": "write_file", "annotations": { "readOnlyHint": false, "destructiveHint": false } },
            { "name": "delete_file" },
        ], "nextCursor": "c2" } })
    }

    fn call(id: i64, name: &str) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": name, "arguments": {} } })
    }

    fn names(msg: &Value) -> Vec<&str> {
        msg["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect()
    }

    fn listed(p: &mut SessionPolicy) -> Value {
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" });
        assert_eq!(p.inbound(&req), Inbound::Forward);
        p.outbound(listing())
    }

    #[test]
    fn read_only_shows_and_allows_only_tools_marked_read_only() {
        let mut p = SessionPolicy::new(ToolPolicy::ReadOnly, Confirm::Never);
        // Before the server has listed anything, nothing is known to be read-only.
        assert!(matches!(
            p.inbound(&call(2, "read_file")),
            Inbound::Refuse(_)
        ));
        let out = listed(&mut p);
        assert_eq!(names(&out), ["read_file"]);
        assert_eq!(out["result"]["nextCursor"], "c2");
        assert_eq!(p.inbound(&call(3, "read_file")), Inbound::Forward);
        assert_eq!(
            p.inbound(&call(4, "delete_file")),
            Inbound::Refuse(
                json!({ "jsonrpc": "2.0", "id": 4, "error": { "code": -32001,
                "message": "This machine does not allow the tool \"delete_file\". Its owner can allow it with `webmcp tools`." } })
            )
        );
    }

    #[test]
    fn an_allow_list_is_exact_and_all_changes_nothing() {
        let mut p = SessionPolicy::new(
            ToolPolicy::Allow(["write_file".to_string()].into()),
            Confirm::Never,
        );
        assert_eq!(names(&listed(&mut p)), ["write_file"]);
        assert_eq!(p.inbound(&call(2, "write_file")), Inbound::Forward);
        assert!(matches!(
            p.inbound(&call(3, "Write_file")),
            Inbound::Refuse(_)
        ));
        assert!(matches!(
            p.inbound(&call(4, "write_file ")),
            Inbound::Refuse(_)
        ));

        let mut all = SessionPolicy::default();
        assert_eq!(listed(&mut all), listing());
    }

    #[test]
    fn confirmation_follows_the_hints_and_mcp_defaults() {
        let mut p = SessionPolicy::new(ToolPolicy::All, Confirm::Destructive);
        // Unlisted: assumed able to change things.
        assert_eq!(
            p.inbound(&call(2, "read_file")),
            Inbound::Confirm {
                tool: "read_file".into()
            }
        );
        listed(&mut p);
        assert_eq!(p.inbound(&call(3, "read_file")), Inbound::Forward);
        assert_eq!(p.inbound(&call(4, "write_file")), Inbound::Forward);
        assert_eq!(
            p.inbound(&call(5, "delete_file")),
            Inbound::Confirm {
                tool: "delete_file".into()
            }
        );
        let mut always = SessionPolicy::new(ToolPolicy::All, Confirm::Always);
        listed(&mut always);
        assert!(matches!(
            always.inbound(&call(6, "read_file")),
            Inbound::Confirm { .. }
        ));
    }

    #[test]
    fn malformed_calls_batches_and_id_less_requests_never_reach_the_server() {
        let mut p = SessionPolicy::default();
        let no_name = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {} });
        assert_eq!(
            p.inbound(&no_name),
            Inbound::Refuse(rpc_error(
                json!(7),
                RPC_INVALID_PARAMS,
                "tools/call needs a tool name of 1 to 128 characters"
            ))
        );
        assert!(matches!(
            p.inbound(&call(8, &"x".repeat(129))),
            Inbound::Refuse(_)
        ));
        assert!(matches!(
            p.inbound(&json!([call(9, "read_file")])),
            Inbound::Refuse(_)
        ));
        let sneaky = json!({ "jsonrpc": "2.0", "method": "tools/call", "params": { "name": "delete_file" } });
        assert_eq!(p.inbound(&sneaky), Inbound::Drop);
        let null_id = json!({ "jsonrpc": "2.0", "id": null, "method": "tools/call", "params": { "name": "x" } });
        assert_eq!(p.inbound(&null_id), Inbound::Drop);
        let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert_eq!(p.inbound(&note), Inbound::Forward);
        let answer = json!({ "jsonrpc": "2.0", "id": "srv-1", "result": {} });
        assert_eq!(p.inbound(&answer), Inbound::Forward);
    }

    #[test]
    fn only_answers_to_tools_list_are_filtered() {
        let mut p = SessionPolicy::new(ToolPolicy::ReadOnly, Confirm::Never);
        // Same id, but it answered some other request: untouched.
        assert_eq!(p.outbound(listing()), listing());
        // A server-sent request that happens to carry a result-like shape.
        let req =
            json!({ "jsonrpc": "2.0", "id": 1, "method": "sampling/createMessage", "params": {} });
        assert_eq!(p.outbound(req.clone()), req);
    }

    #[test]
    fn policies_round_trip_through_toml() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct E {
            tools: ToolPolicy,
            confirm: Confirm,
        }
        for (e, text) in [
            (
                E {
                    tools: ToolPolicy::All,
                    confirm: Confirm::Never,
                },
                "tools = \"all\"\nconfirm = \"never\"\n",
            ),
            (
                E {
                    tools: ToolPolicy::ReadOnly,
                    confirm: Confirm::Destructive,
                },
                "tools = \"read_only\"\nconfirm = \"destructive\"\n",
            ),
            (
                E {
                    tools: ToolPolicy::Allow(["a".into(), "b".into()].into()),
                    confirm: Confirm::Always,
                },
                "confirm = \"always\"\n\n[tools]\nallow = [\"a\", \"b\"]\n",
            ),
        ] {
            let s = toml::to_string(&e).unwrap();
            assert_eq!(s, text);
            assert_eq!(toml::from_str::<E>(&s).unwrap(), e);
        }
    }
}
