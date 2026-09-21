//! Minimal Server-Sent Events decoder: enough for MCP Streamable HTTP,
//! where every event's `data` is one JSON-RPC message.

/// Incremental parser. Feed it body chunks; it yields each completed
/// event's `data` payload.
#[derive(Default)]
pub(super) struct SseParser {
    /// Bytes of the current, still incomplete line.
    line: Vec<u8>,
    /// `data:` lines of the current event, joined with `\n`.
    data: String,
    has_data: bool,
}

impl SseParser {
    /// Bytes held for the event in progress (for size limits).
    pub fn buffered(&self) -> usize {
        self.line.len() + self.data.len()
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<String> {
        let mut events = Vec::new();
        for &byte in chunk {
            if byte != b'\n' {
                self.line.push(byte);
                continue;
            }
            let mut line = std::mem::take(&mut self.line);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() {
                // Blank line: dispatch.
                if std::mem::take(&mut self.has_data) {
                    events.push(std::mem::take(&mut self.data));
                }
                continue;
            }
            let text = String::from_utf8_lossy(&line);
            let (field, value) = match text.split_once(':') {
                // A leading colon is a comment (often a keep-alive).
                Some(("", _)) => continue,
                Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
                None => (text.as_ref(), ""),
            };
            // `event`, `id` and `retry` carry nothing the relay needs.
            if field == "data" {
                if self.has_data {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.has_data = true;
            }
        }
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_across_chunks_and_line_endings() {
        let mut p = SseParser::default();
        assert!(p.push(b": ping\n\nevent: message\ndata: {\"a\"").is_empty());
        assert_eq!(p.push(b":1}\r\n\r\ndata:x\ndata: y\n"), ["{\"a\":1}"]);
        assert!(p.buffered() > 0);
        assert_eq!(p.push(b"\nid: 7\n\n"), ["x\ny"]);
        assert_eq!(p.buffered(), 0);
    }

    #[test]
    fn unterminated_event_is_not_dispatched() {
        let mut p = SseParser::default();
        assert!(p.push(b"data: {}\n").is_empty());
    }
}
