//! Secret redaction in output.

use regex::Regex;

/// Common secret patterns to redact.
const SECRET_PATTERNS: &[(&str, &str)] = &[
    // API keys and tokens
    (
        r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?"#,
        "$1=<REDACTED>",
    ),
    (
        r#"(?i)(secret[_-]?key|secretkey)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?"#,
        "$1=<REDACTED>",
    ),
    (
        r#"(?i)(access[_-]?token|accesstoken)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?"#,
        "$1=<REDACTED>",
    ),
    (
        r#"(?i)(auth[_-]?token|authtoken)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?"#,
        "$1=<REDACTED>",
    ),
    // Bearer tokens
    (r"(?i)(bearer\s+)([a-zA-Z0-9_\-\.]{20,})", "$1<REDACTED>"),
    // AWS
    (r"AKIA[0-9A-Z]{16}", "<AWS_ACCESS_KEY_REDACTED>"),
    (
        r#"(?i)(aws_secret_access_key)\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?"#,
        "$1=<REDACTED>",
    ),
    // GitHub
    (r"ghp_[a-zA-Z0-9]{36}", "<GITHUB_TOKEN_REDACTED>"),
    (r"gho_[a-zA-Z0-9]{36}", "<GITHUB_OAUTH_REDACTED>"),
    (r"github_pat_[a-zA-Z0-9_]{22,}", "<GITHUB_PAT_REDACTED>"),
    // Passwords
    (
        r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{8,})['"]?"#,
        "$1=<REDACTED>",
    ),
    // Private keys
    (
        r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----<REDACTED>",
    ),
    // Generic secrets
    (
        r#"(?i)(secret|credential|token)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{16,})['"]?"#,
        "$1=<REDACTED>",
    ),
];

/// Redact secrets from text.
pub fn redact_secrets(text: &str) -> String {
    let mut result = text.to_string();

    for (pattern, replacement) in SECRET_PATTERNS {
        if let Ok(re) = Regex::new(pattern) {
            result = re.replace_all(&result, *replacement).to_string();
        }
    }

    result
}

/// Check if text contains potential secrets.
#[allow(dead_code)]
pub fn contains_secrets(text: &str) -> bool {
    for (pattern, _) in SECRET_PATTERNS {
        if let Ok(re) = Regex::new(pattern)
            && re.is_match(text)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_api_key() {
        let text = "api_key=sk_live_1234567890abcdefghijklmnop";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("1234567890"));
        assert!(redacted.contains("<REDACTED>"));
    }

    #[test]
    fn test_redact_bearer_token() {
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("eyJhbGci"));
        assert!(redacted.contains("<REDACTED>"));
    }

    #[test]
    fn test_redact_aws_key() {
        let text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(redacted.contains("<AWS_ACCESS_KEY_REDACTED>"));
    }

    #[test]
    fn test_redact_github_token() {
        let text = "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("ghp_"));
        assert!(redacted.contains("<GITHUB_TOKEN_REDACTED>"));
    }

    #[test]
    fn test_redact_password() {
        let text = "password=mysecretpassword123";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("mysecretpassword"));
        assert!(redacted.contains("<REDACTED>"));
    }

    #[test]
    fn test_redact_private_key() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let redacted = redact_secrets(text);
        assert!(redacted.contains("<REDACTED>"));
    }

    #[test]
    fn test_contains_secrets() {
        assert!(contains_secrets("api_key=abcdefghij1234567890"));
        assert!(contains_secrets("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        assert!(!contains_secrets("Hello, world!"));
    }

    #[test]
    fn test_no_secrets() {
        let text = "This is just normal text without any secrets";
        let redacted = redact_secrets(text);
        assert_eq!(text, redacted);
    }
}
