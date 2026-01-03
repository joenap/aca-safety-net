//! Heroku CLI analysis - blocks commands that expose secrets.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Analyze Heroku CLI commands for secret exposure.
pub fn analyze_heroku(tokens: &[Token], _config: &CompiledConfig) -> Decision {
    let words: Vec<&str> = tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect();

    if words.len() < 2 {
        return Decision::allow();
    }

    // Check subcommand (words[1])
    match words[1] {
        // Auth token exposure
        "auth:token" => Decision::block(
            "heroku.auth.token",
            "heroku auth:token exposes authentication token",
        ),

        // Config/env var exposure
        "config" => Decision::block(
            "heroku.config",
            "heroku config exposes environment variables which may contain secrets",
        ),
        "config:get" => Decision::block(
            "heroku.config.get",
            "heroku config:get exposes environment variable values",
        ),

        // Database credentials
        "pg:credentials" => Decision::block(
            "heroku.pg.credentials",
            "heroku pg:credentials exposes database credentials",
        ),
        "pg:credentials:url" => Decision::block(
            "heroku.pg.credentials",
            "heroku pg:credentials:url exposes database connection string with credentials",
        ),

        // Redis credentials
        "redis:credentials" => Decision::block(
            "heroku.redis.credentials",
            "heroku redis:credentials exposes Redis credentials",
        ),

        // Allow all other commands
        _ => Decision::allow(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::shell::tokenize;

    fn test_config() -> CompiledConfig {
        Config::default().compile().unwrap()
    }

    // Blocked commands

    #[test]
    fn test_auth_token() {
        let config = test_config();
        let tokens = tokenize("heroku auth:token");
        let decision = analyze_heroku(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_heroku_config() {
        let config = test_config();
        let tokens = tokenize("heroku config");
        let decision = analyze_heroku(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_heroku_config_with_app() {
        let config = test_config();
        let tokens = tokenize("heroku config -a myapp");
        let decision = analyze_heroku(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_config_get() {
        let config = test_config();
        let tokens = tokenize("heroku config:get DATABASE_URL");
        let decision = analyze_heroku(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_pg_credentials() {
        let config = test_config();
        let tokens = tokenize("heroku pg:credentials");
        let decision = analyze_heroku(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_pg_credentials_url() {
        let config = test_config();
        let tokens = tokenize("heroku pg:credentials:url");
        let decision = analyze_heroku(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_redis_credentials() {
        let config = test_config();
        let tokens = tokenize("heroku redis:credentials");
        let decision = analyze_heroku(&tokens, &config);
        assert!(decision.is_blocked());
    }

    // Allowed commands

    #[test]
    fn test_apps_allowed() {
        let config = test_config();
        let tokens = tokenize("heroku apps");
        let decision = analyze_heroku(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_ps_allowed() {
        let config = test_config();
        let tokens = tokenize("heroku ps");
        let decision = analyze_heroku(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_logs_allowed() {
        let config = test_config();
        let tokens = tokenize("heroku logs --tail");
        let decision = analyze_heroku(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_info_allowed() {
        let config = test_config();
        let tokens = tokenize("heroku info");
        let decision = analyze_heroku(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_run_allowed() {
        let config = test_config();
        let tokens = tokenize("heroku run bash");
        let decision = analyze_heroku(&tokens, &config);
        assert!(!decision.is_blocked());
    }
}
