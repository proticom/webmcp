//! Asking the owner, on this machine, whether one tool call may run: a
//! dialog with Allow and Deny that denies on its own after a minute. Where no
//! dialog can be shown (no desktop session, an unsupported platform), the
//! answer is Deny.

use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info};

use crate::approvals::{clean_name, printable};

/// How long a dialog waits before it counts as Deny.
pub const ANSWER_WITHIN: Duration = Duration::from_secs(60);

/// One call waiting for the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    /// The agent's name as the gateway reported it; shown, never trusted.
    pub agent: String,
    pub alias: String,
    pub tool: String,
    /// The call's arguments, compact JSON; shown clipped.
    pub arguments: String,
}

/// Longest argument summary a dialog shows.
const ARGUMENTS_SHOWN: usize = 400;

impl Ask {
    pub fn text(&self) -> String {
        let agent = match clean_name(&self.agent) {
            n if n.is_empty() => "An agent".to_string(),
            // The gateway reports this name; nothing on this machine checked it.
            n => format!("An agent calling itself \"{n}\""),
        };
        let tool = clean_name(&self.tool);
        let spaced: String = self
            .arguments
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let mut args = printable(spaced.trim());
        if args.chars().count() > ARGUMENTS_SHOWN {
            args = args.chars().take(ARGUMENTS_SHOWN).collect::<String>() + "…";
        }
        format!(
            "{agent} wants to run the tool \"{tool}\" on {} with:\n\n{args}\n\nAllow it this once?",
            self.alias
        )
    }
}

pub type Answer = Pin<Box<dyn Future<Output = bool> + Send>>;
/// Answers an [`Ask`]: `true` is Allow.
pub type Confirmer = Arc<dyn Fn(Ask) -> Answer + Send + Sync>;

/// The platform dialog.
pub fn system() -> Confirmer {
    Arc::new(|ask: Ask| Box::pin(dialog(ask)))
}

/// Always the same answer; for tests and for a machine with no desktop.
pub fn fixed(allow: bool) -> Confirmer {
    Arc::new(move |_| Box::pin(async move { allow }))
}

/// The dialog's program and argv. The text is data after `--` (macOS) or a
/// single argument (zenity), never spliced into a script or a shell.
fn dialog_command(text: String) -> Option<(&'static str, Vec<String>)> {
    let secs = ANSWER_WITHIN.as_secs().to_string();
    if cfg!(target_os = "macos") {
        let script = [
            "on run argv".to_string(),
            format!(
                "display dialog (item 1 of argv) with title \"webmcp\" buttons {{\"Deny\", \"Allow\"}} default button \"Deny\" cancel button \"Deny\" with icon caution giving up after {secs}"
            ),
            "end run".to_string(),
        ];
        let mut args: Vec<String> = script
            .into_iter()
            .flat_map(|line| ["-e".to_string(), line])
            .collect();
        args.extend(["--".to_string(), text]);
        Some(("osascript", args))
    } else if cfg!(target_os = "linux") {
        Some((
            "zenity",
            vec![
                "--question".into(),
                "--title=webmcp".into(),
                "--ok-label=Allow".into(),
                "--cancel-label=Deny".into(),
                format!("--timeout={secs}"),
                "--no-markup".into(),
                format!("--text={text}"),
            ],
        ))
    } else {
        None
    }
}

/// Allow only on an explicit Allow: a timeout, Deny, a closed window or a
/// missing dialog program all deny.
fn allowed(program: &str, success: bool, stdout: &str) -> bool {
    match program {
        "osascript" => {
            success && stdout.contains("button returned:Allow") && !stdout.contains("gave up:true")
        }
        _ => success,
    }
}

async fn dialog(ask: Ask) -> bool {
    let Some((program, args)) = dialog_command(ask.text()) else {
        info!(tool = %ask.tool, server = %ask.alias, "no confirmation dialog on this platform; denied");
        return false;
    };
    let run = tokio::process::Command::new(program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output();
    let out = match tokio::time::timeout(ANSWER_WITHIN + Duration::from_secs(5), run).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            debug!(error = %e, program, "confirmation dialog could not start; denied");
            return false;
        }
        Err(_) => return false,
    };
    let yes = allowed(
        program,
        out.status.success(),
        &String::from_utf8_lossy(&out.stdout),
    );
    info!(tool = %ask.tool, server = %ask.alias, allowed = yes, "owner answered a confirmation");
    yes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_text_is_clean_and_names_what_will_run() {
        let ask = Ask {
            agent: "Claude\u{202E}exe.".into(),
            alias: "fs".into(),
            tool: "delete_file".into(),
            arguments: "{\"path\":\"~/x\u{200B}\ny\"}".into(),
        };
        assert_eq!(
            ask.text(),
            "An agent calling itself \"Claudeexe.\" wants to run the tool \"delete_file\" on fs with:\n\n{\"path\":\"~/x y\"}\n\nAllow it this once?"
        );
        let anon = Ask {
            agent: " ".into(),
            arguments: "x".repeat(1000),
            ..ask
        };
        let text = anon.text();
        assert!(text.starts_with("An agent wants"));
        assert!(text.contains(&format!("{}…\n", "x".repeat(400))));
    }

    #[test]
    fn only_an_explicit_allow_counts() {
        assert!(allowed(
            "osascript",
            true,
            "button returned:Allow, gave up:false\n"
        ));
        assert!(!allowed(
            "osascript",
            true,
            "button returned:, gave up:true\n"
        ));
        assert!(!allowed("osascript", false, ""));
        assert!(!allowed("osascript", true, "button returned:Deny\n"));
        assert!(allowed("zenity", true, ""));
        assert!(!allowed("zenity", false, ""));
    }

    #[test]
    fn the_dialog_text_is_passed_as_data() {
        let evil = "-e do shell script \"rm -rf ~\"".to_string();
        let (program, args) = dialog_command(evil.clone()).expect("a dialog on this platform");
        if program == "osascript" {
            let dashdash = args.iter().position(|a| a == "--").unwrap();
            assert_eq!(args[dashdash + 1..], [evil]);
            assert!(args[..dashdash].iter().all(|a| !a.contains("rm -rf")));
        } else {
            assert_eq!(args.last().unwrap(), &format!("--text={evil}"));
        }
    }
}
