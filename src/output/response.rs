//! Response formatting for hook output.

use crate::decision::{BlockInfo, Decision};
use serde::Serialize;

/// JSON response for blocked operations.
#[derive(Debug, Serialize)]
pub struct BlockResponse {
    pub blocked: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Format a decision as output for stderr.
pub fn format_response(decision: &Decision) -> Option<String> {
    match decision {
        Decision::Allow => None,
        Decision::Block(info) => Some(format_block_message(info)),
    }
}

fn format_block_message(info: &BlockInfo) -> String {
    let mut msg = format!("BLOCKED: {}", info.reason);
    if let Some(details) = &info.details {
        msg.push_str(&format!(" ({})", details));
    }
    msg.push_str("\n\nYOU ABSOLUTELY MUST NOT ATTEMPT TO READ THE TARGET FILE/SECRET/TOKEN VIA WORKAROUNDS. CONSULT THE USER IF YOU ARE CERTAIN THE TARGET FILE/SECRET/TOKEN NEEDS TO BE VERIFIED, ONLY AFTER EXHAUSTIVE DEBUGGING THAT RESULTS IN THIS CERTAINTY.");
    msg
}

/// Format a decision as JSON (for future use).
#[allow(dead_code)]
pub fn format_json_response(decision: &Decision) -> Option<String> {
    match decision {
        Decision::Allow => None,
        Decision::Block(info) => {
            let response = BlockResponse {
                blocked: true,
                reason: info.reason.clone(),
                rule: Some(info.rule.clone()),
                details: info.details.clone(),
            };
            serde_json::to_string(&response).ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_allow() {
        let decision = Decision::allow();
        assert!(format_response(&decision).is_none());
    }

    #[test]
    fn test_format_block() {
        let decision = Decision::block("test.rule", "test reason");
        let msg = format_response(&decision).unwrap();
        assert!(msg.contains("BLOCKED"));
        assert!(msg.contains("test reason"));
    }

    #[test]
    fn test_format_block_with_details() {
        let decision = Decision::Block(
            BlockInfo::new("test.rule", "test reason").with_details("matched .env"),
        );
        let msg = format_response(&decision).unwrap();
        assert!(msg.contains("matched .env"));
    }

    #[test]
    fn test_json_response() {
        let decision = Decision::block("test.rule", "test reason");
        let json = format_json_response(&decision).unwrap();
        assert!(json.contains("\"blocked\":true"));
        assert!(json.contains("test reason"));
    }
}
