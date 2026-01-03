//! Bash tool analysis.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::input::BashInput;
use crate::rules::{analyze_command, check_custom_rules, check_sensitive_path};
use crate::shell::{split_commands, strip_wrappers, tokenize, Token};

/// Analyze a Bash tool invocation.
pub fn analyze_bash(input: &BashInput, config: &CompiledConfig, cwd: Option<&str>) -> Decision {
    let command = &input.command;

    // 1. Check explicit deny rules
    for (rule, re) in &config.deny_patterns {
        if rule.tool == "Bash" && re.is_match(command) {
            return Decision::block(&rule.reason, &rule.reason);
        }
    }

    // 2. Check custom rules
    let custom_decision = check_custom_rules("Bash", command, config);
    if custom_decision.is_blocked() {
        return custom_decision;
    }

    // 3. Paranoid mode check
    if let Some(pattern) = config.matches_paranoid(command) {
        return Decision::block(
            "paranoid.sensitive_mention",
            format!("command mentions sensitive pattern '{}'", pattern),
        );
    }

    // 4. Check read commands + sensitive files
    if config.is_read_command(command) {
        // Check all segments for sensitive file access
        let segments = split_commands(command);
        for segment in &segments {
            let stripped = strip_wrappers(&segment.command);
            let tokens = tokenize(&stripped);

            // Check all words that look like paths
            for token in &tokens {
                if let Token::Word(word) = token {
                    // Skip if it looks like an option
                    if word.starts_with('-') {
                        continue;
                    }
                    // Check if it matches sensitive pattern
                    let decision = check_sensitive_path(word, config);
                    if decision.is_blocked() {
                        return decision;
                    }
                }
            }
        }
    }

    // 5. Check for git add on sensitive files
    let segments = split_commands(command);
    for segment in &segments {
        let stripped = strip_wrappers(&segment.command);
        let tokens = tokenize(&stripped);

        let words: Vec<&str> = tokens
            .iter()
            .filter_map(|t| match t {
                Token::Word(w) => Some(w.as_str()),
                _ => None,
            })
            .collect();

        if words.len() >= 2 && words[0] == "git" && words[1] == "add" {
            for path in &words[2..] {
                if path.starts_with('-') {
                    continue;
                }
                let decision = check_sensitive_path(path, config);
                if decision.is_blocked() {
                    return Decision::block(
                        "git.add.sensitive",
                        format!("git add on sensitive file: {}", path),
                    );
                }
            }
        }
    }

    // 6. Analyze command segments for built-in rules
    analyze_command(command, config, cwd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, DenyRule, ParanoidConfig};

    fn test_config() -> CompiledConfig {
        Config {
            sensitive_files: vec![r"\.env\b".to_string(), r"id_rsa".to_string()],
            read_commands: Some(r"\b(cat|head|tail|grep)\b".to_string()),
            deny: vec![DenyRule {
                tool: "Bash".to_string(),
                pattern: r"^printenv".to_string(),
                reason: "Exposes environment variables".to_string(),
            }],
            paranoid: ParanoidConfig {
                enabled: false,
                extra_patterns: vec![],
            },
            git: crate::config::GitConfig {
                block_add_sensitive: true,
                ..Default::default()
            },
            ..Default::default()
        }
        .compile()
        .unwrap()
    }

    fn paranoid_config() -> CompiledConfig {
        Config {
            sensitive_files: vec![r"\.env\b".to_string()],
            paranoid: ParanoidConfig {
                enabled: true,
                extra_patterns: vec![],
            },
            ..Default::default()
        }
        .compile()
        .unwrap()
    }

    #[test]
    fn test_deny_rule() {
        let config = test_config();
        let input = BashInput {
            command: "printenv PATH".to_string(),
            timeout: None,
            description: None,
        };
        let decision = analyze_bash(&input, &config, None);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_read_sensitive() {
        let config = test_config();
        let input = BashInput {
            command: "cat .env".to_string(),
            timeout: None,
            description: None,
        };
        let decision = analyze_bash(&input, &config, None);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_grep_sensitive() {
        let config = test_config();
        let input = BashInput {
            command: "grep password ~/.ssh/id_rsa".to_string(),
            timeout: None,
            description: None,
        };
        let decision = analyze_bash(&input, &config, None);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_paranoid_mode() {
        let config = paranoid_config();
        let input = BashInput {
            command: "ls .env".to_string(), // Not a read command, but mentions .env
            timeout: None,
            description: None,
        };
        let decision = analyze_bash(&input, &config, None);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_add_sensitive() {
        let config = test_config();
        let input = BashInput {
            command: "git add .env".to_string(),
            timeout: None,
            description: None,
        };
        let decision = analyze_bash(&input, &config, None);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_safe_command() {
        let config = test_config();
        let input = BashInput {
            command: "ls -la".to_string(),
            timeout: None,
            description: None,
        };
        let decision = analyze_bash(&input, &config, None);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_cat_normal_file() {
        let config = test_config();
        let input = BashInput {
            command: "cat src/main.rs".to_string(),
            timeout: None,
            description: None,
        };
        let decision = analyze_bash(&input, &config, None);
        assert!(!decision.is_blocked());
    }
}
