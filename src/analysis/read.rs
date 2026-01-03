//! Read tool analysis.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::input::ReadInput;
use crate::rules::{check_custom_rules, check_sensitive_path};

/// Analyze a Read tool invocation.
pub fn analyze_read(input: &ReadInput, config: &CompiledConfig) -> Decision {
    let path = &input.file_path;

    // 1. Check explicit deny rules
    for (rule, re) in &config.deny_patterns {
        if rule.tool == "Read" && re.is_match(path) {
            return Decision::block(&rule.reason, &rule.reason);
        }
    }

    // 2. Check custom rules
    let custom_decision = check_custom_rules("Read", path, config);
    if custom_decision.is_blocked() {
        return custom_decision;
    }

    // 3. Paranoid mode check
    if let Some(pattern) = config.matches_paranoid(path) {
        return Decision::block(
            "paranoid.sensitive_file",
            format!("file path matches sensitive pattern '{}'", pattern),
        );
    }

    // 4. Check sensitive file patterns
    check_sensitive_path(path, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, DenyRule, ParanoidConfig};

    fn test_config() -> CompiledConfig {
        Config {
            sensitive_files: vec![
                r"\.env\b".to_string(),
                r"\.pem$".to_string(),
                r"id_rsa".to_string(),
                r"\.aws/credentials".to_string(),
            ],
            deny: vec![DenyRule {
                tool: "Read".to_string(),
                pattern: r"/etc/shadow".to_string(),
                reason: "Cannot read shadow file".to_string(),
            }],
            ..Default::default()
        }
        .compile()
        .unwrap()
    }

    #[test]
    fn test_read_env() {
        let config = test_config();
        let input = ReadInput {
            file_path: "/home/user/project/.env".to_string(),
            offset: None,
            limit: None,
        };
        let decision = analyze_read(&input, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_read_env_local() {
        let config = test_config();
        let input = ReadInput {
            file_path: ".env.local".to_string(),
            offset: None,
            limit: None,
        };
        let decision = analyze_read(&input, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_read_pem() {
        let config = test_config();
        let input = ReadInput {
            file_path: "/etc/ssl/certs/server.pem".to_string(),
            offset: None,
            limit: None,
        };
        let decision = analyze_read(&input, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_read_ssh_key() {
        let config = test_config();
        let input = ReadInput {
            file_path: "/home/user/.ssh/id_rsa".to_string(),
            offset: None,
            limit: None,
        };
        let decision = analyze_read(&input, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_read_aws_credentials() {
        let config = test_config();
        let input = ReadInput {
            file_path: "/home/user/.aws/credentials".to_string(),
            offset: None,
            limit: None,
        };
        let decision = analyze_read(&input, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_deny_rule() {
        let config = test_config();
        let input = ReadInput {
            file_path: "/etc/shadow".to_string(),
            offset: None,
            limit: None,
        };
        let decision = analyze_read(&input, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_read_normal_file() {
        let config = test_config();
        let input = ReadInput {
            file_path: "/home/user/project/src/main.rs".to_string(),
            offset: None,
            limit: None,
        };
        let decision = analyze_read(&input, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_read_cargo_toml() {
        let config = test_config();
        let input = ReadInput {
            file_path: "Cargo.toml".to_string(),
            offset: None,
            limit: None,
        };
        let decision = analyze_read(&input, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_environment_not_env() {
        let config = test_config();
        let input = ReadInput {
            file_path: "src/environment.ts".to_string(),
            offset: None,
            limit: None,
        };
        let decision = analyze_read(&input, &config);
        assert!(!decision.is_blocked()); // .env\b pattern shouldn't match
    }
}
