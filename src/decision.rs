//! Decision types for hook responses.

use serde::Serialize;

/// The result of analyzing a tool invocation.
#[derive(Debug, Clone)]
pub enum Decision {
    /// Allow the tool to proceed.
    Allow,
    /// Block the tool with a reason.
    Block(BlockInfo),
    /// Ask the user for approval.
    Ask(AskInfo),
}

/// Information about why a tool was blocked.
#[derive(Debug, Clone, Serialize)]
pub struct BlockInfo {
    /// Human-readable reason for blocking.
    pub reason: String,
    /// The rule that triggered the block.
    pub rule: String,
    /// Optional details (e.g., matched pattern).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Information about why user approval is required.
#[derive(Debug, Clone, Serialize)]
pub struct AskInfo {
    /// Human-readable reason for asking.
    pub reason: String,
    /// The rule that triggered the ask.
    pub rule: String,
    /// Suggestion for alternative approach.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

impl BlockInfo {
    pub fn new(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            reason: reason.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

impl AskInfo {
    pub fn new(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            reason: reason.into(),
            suggestion: None,
        }
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestion = Some(suggestion.into());
        self
    }
}

impl Decision {
    /// Create an allow decision.
    pub fn allow() -> Self {
        Decision::Allow
    }

    /// Create a block decision.
    pub fn block(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Decision::Block(BlockInfo::new(rule, reason))
    }

    /// Create an ask decision (requires user approval).
    pub fn ask(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Decision::Ask(AskInfo::new(rule, reason))
    }

    /// Check if this is a block decision.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Decision::Block(_))
    }

    /// Check if this requires user approval.
    pub fn is_ask(&self) -> bool {
        matches!(self, Decision::Ask(_))
    }

    /// Get the block info if blocked.
    pub fn block_info(&self) -> Option<&BlockInfo> {
        match self {
            Decision::Block(info) => Some(info),
            _ => None,
        }
    }

    /// Get the ask info if asking.
    pub fn ask_info(&self) -> Option<&AskInfo> {
        match self {
            Decision::Ask(info) => Some(info),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow() {
        let d = Decision::allow();
        assert!(!d.is_blocked());
        assert!(d.block_info().is_none());
    }

    #[test]
    fn test_block() {
        let d = Decision::block("test_rule", "test reason");
        assert!(d.is_blocked());
        let info = d.block_info().unwrap();
        assert_eq!(info.rule, "test_rule");
        assert_eq!(info.reason, "test reason");
    }

    #[test]
    fn test_block_with_details() {
        let d = Decision::Block(BlockInfo::new("rule", "reason").with_details("matched: .env"));
        assert!(d.block_info().unwrap().details.is_some());
    }
}
