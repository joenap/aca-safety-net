//! Sensitive file and secrets detection.

use crate::config::CompiledConfig;
use crate::decision::Decision;

/// Check if a file path matches sensitive patterns.
pub fn check_sensitive_path(path: &str, config: &CompiledConfig) -> Decision {
    if let Some(pattern) = config.is_sensitive_path(path) {
        return Decision::block(
            "secrets.sensitive_file",
            format!("access to sensitive file matching '{}'", pattern),
        );
    }
    Decision::allow()
}

/// Check if git add is targeting sensitive files.
pub fn check_git_add_sensitive(paths: &[&str], config: &CompiledConfig) -> Decision {
    if !config.raw.git.block_add_sensitive {
        return Decision::allow();
    }

    for path in paths {
        if let Some(pattern) = config.is_sensitive_path(path) {
            return Decision::block(
                "git.add.sensitive",
                format!("git add on sensitive file matching '{}'", pattern),
            );
        }
    }

    Decision::allow()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_config() -> CompiledConfig {
        Config {
            sensitive_files: vec![
                r"\.env\b".to_string(),
                r"\.pem$".to_string(),
                r"id_rsa".to_string(),
            ],
            git: crate::config::GitConfig {
                block_add_sensitive: true,
                ..Default::default()
            },
            ..Default::default()
        }
        .compile()
        .unwrap()
    }

    #[test]
    fn test_sensitive_env() {
        let config = test_config();
        let decision = check_sensitive_path(".env", &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_sensitive_env_local() {
        let config = test_config();
        let decision = check_sensitive_path(".env.local", &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_sensitive_pem() {
        let config = test_config();
        let decision = check_sensitive_path("/etc/ssl/private/server.pem", &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_sensitive_ssh_key() {
        let config = test_config();
        let decision = check_sensitive_path("/home/user/.ssh/id_rsa", &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_not_sensitive() {
        let config = test_config();
        let decision = check_sensitive_path("src/main.rs", &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_environment_not_env() {
        let config = test_config();
        let decision = check_sensitive_path("environment.ts", &config);
        assert!(!decision.is_blocked()); // .env\b should not match environment
    }

    #[test]
    fn test_git_add_sensitive() {
        let config = test_config();
        let decision = check_git_add_sensitive(&[".env", "src/main.rs"], &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_add_normal() {
        let config = test_config();
        let decision = check_git_add_sensitive(&["src/main.rs", "Cargo.toml"], &config);
        assert!(!decision.is_blocked());
    }
}
