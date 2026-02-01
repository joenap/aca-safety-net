//! Audit logging for security events.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::decision::Decision;
use crate::input::HookInput;

/// An audit log entry.
#[derive(Debug, Serialize)]
pub struct AuditEntry {
    /// Timestamp of the event.
    pub timestamp: DateTime<Utc>,
    /// Session ID if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Tool that was invoked.
    pub tool: String,
    /// Whether the operation was blocked.
    pub blocked: bool,
    /// Whether user approval was requested.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub asked: bool,
    /// Rule that triggered the block/ask (if blocked or asked).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Reason for blocking/asking (if blocked or asked).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Summary of the operation (command or path).
    pub summary: String,
}

impl AuditEntry {
    /// Create a new audit entry from hook input and decision.
    pub fn new(input: &HookInput, decision: &Decision) -> Self {
        let (blocked, asked, rule, reason) = match decision {
            Decision::Allow => (false, false, None, None),
            Decision::Block(info) => {
                (true, false, Some(info.rule.clone()), Some(info.reason.clone()))
            }
            Decision::Ask(info) => {
                (false, true, Some(info.rule.clone()), Some(info.reason.clone()))
            }
        };

        let summary = input
            .command()
            .map(|c| truncate_string(c, 200))
            .or_else(|| input.file_path().map(String::from))
            .unwrap_or_else(|| "<unknown>".to_string());

        Self {
            timestamp: Utc::now(),
            session_id: input.session_id.clone(),
            tool: input.tool_name.clone(),
            blocked,
            asked,
            rule,
            reason,
            summary,
        }
    }
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Audit logger for writing entries to a file.
pub struct AuditLogger {
    file: File,
}

impl AuditLogger {
    /// Open or create an audit log file.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self { file })
    }

    /// Write an audit entry to the log.
    pub fn log(&mut self, entry: &AuditEntry) -> std::io::Result<()> {
        let json = serde_json::to_string(entry)?;
        writeln!(self.file, "{}", json)?;
        self.file.flush()
    }

    /// Log a decision for an input.
    pub fn log_decision(&mut self, input: &HookInput, decision: &Decision) -> std::io::Result<()> {
        let entry = AuditEntry::new(input, decision);
        self.log(&entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_audit_entry_allow() {
        let input = HookInput::parse(r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#)
            .unwrap();
        let decision = Decision::allow();
        let entry = AuditEntry::new(&input, &decision);

        assert_eq!(entry.tool, "Bash");
        assert!(!entry.blocked);
        assert!(entry.rule.is_none());
        assert_eq!(entry.summary, "ls -la");
    }

    #[test]
    fn test_audit_entry_block() {
        let input = HookInput::parse(r#"{"tool_name":"Read","tool_input":{"file_path":".env"}}"#)
            .unwrap();
        let decision = Decision::block("test.rule", "test reason");
        let entry = AuditEntry::new(&input, &decision);

        assert_eq!(entry.tool, "Read");
        assert!(entry.blocked);
        assert_eq!(entry.rule, Some("test.rule".to_string()));
        assert_eq!(entry.reason, Some("test reason".to_string()));
        assert_eq!(entry.summary, ".env");
    }

    #[test]
    fn test_audit_logger() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut logger = AuditLogger::open(temp_file.path()).unwrap();

        let input = HookInput::parse(r#"{"tool_name":"Bash","tool_input":{"command":"pwd"}}"#)
            .unwrap();
        let decision = Decision::allow();

        logger.log_decision(&input, &decision).unwrap();

        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("\"tool\":\"Bash\""));
        assert!(content.contains("\"blocked\":false"));
    }

    #[test]
    fn test_truncate_summary() {
        let long_command = "a".repeat(300);
        let input_json = format!(
            r#"{{"tool_name":"Bash","tool_input":{{"command":"{}"}}}}"#,
            long_command
        );
        let input = HookInput::parse(&input_json).unwrap();
        let decision = Decision::allow();
        let entry = AuditEntry::new(&input, &decision);

        assert!(entry.summary.len() <= 200);
        assert!(entry.summary.ends_with("..."));
    }
}
