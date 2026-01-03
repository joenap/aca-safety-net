//! GCloud CLI analysis - blocks commands that expose secrets.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Analyze GCloud CLI commands for secret exposure.
pub fn analyze_gcloud(tokens: &[Token], _config: &CompiledConfig) -> Decision {
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

    // GCloud CLI structure: gcloud <group> <command> [subcommand] [options]
    let group = words[1];

    match group {
        // Auth - token printing
        "auth" => {
            if words.len() < 3 {
                return Decision::allow();
            }
            match words[2] {
                "print-access-token" => Decision::block(
                    "gcloud.auth.token",
                    "gcloud auth print-access-token exposes access token",
                ),
                "print-identity-token" => Decision::block(
                    "gcloud.auth.token",
                    "gcloud auth print-identity-token exposes identity token",
                ),
                "application-default" => {
                    // Check for print-access-token subcommand
                    if words.len() >= 4 && words[3] == "print-access-token" {
                        Decision::block(
                            "gcloud.auth.token",
                            "gcloud auth application-default print-access-token exposes ADC token",
                        )
                    } else {
                        Decision::allow()
                    }
                }
                _ => Decision::allow(),
            }
        }

        // Secrets - version access retrieves secret values
        "secrets" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            // gcloud secrets versions access <version> --secret=<secret>
            if words[2] == "versions" && words[3] == "access" {
                Decision::block(
                    "gcloud.secrets.access",
                    "gcloud secrets versions access exposes secret value",
                )
            } else {
                Decision::allow()
            }
        }

        // SQL - password setting (password in args)
        "sql" => {
            if words.len() < 4 {
                return Decision::allow();
            }
            // gcloud sql users set-password contains password in command
            if words[2] == "users" && words[3] == "set-password" {
                // Check if --password flag is present (password would be in command)
                if words.iter().any(|w| w.starts_with("--password")) {
                    Decision::block(
                        "gcloud.sql.password",
                        "gcloud sql users set-password with --password exposes password in command",
                    )
                } else {
                    Decision::allow()
                }
            } else {
                Decision::allow()
            }
        }

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
    fn test_auth_print_access_token() {
        let config = test_config();
        let tokens = tokenize("gcloud auth print-access-token");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_auth_print_access_token_with_account() {
        let config = test_config();
        let tokens = tokenize("gcloud auth print-access-token user@example.com");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_auth_print_identity_token() {
        let config = test_config();
        let tokens = tokenize("gcloud auth print-identity-token");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_auth_application_default_print_access_token() {
        let config = test_config();
        let tokens = tokenize("gcloud auth application-default print-access-token");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_secrets_versions_access() {
        let config = test_config();
        let tokens = tokenize("gcloud secrets versions access 123 --secret=my-secret");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_secrets_versions_access_latest() {
        let config = test_config();
        let tokens = tokenize("gcloud secrets versions access latest --secret=api-key");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_sql_set_password_with_password() {
        let config = test_config();
        let tokens = tokenize("gcloud sql users set-password root --instance=mydb --password=secret123");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(decision.is_blocked());
    }

    // Allowed commands

    #[test]
    fn test_auth_list_allowed() {
        let config = test_config();
        let tokens = tokenize("gcloud auth list");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_auth_login_allowed() {
        let config = test_config();
        let tokens = tokenize("gcloud auth login");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_auth_application_default_login_allowed() {
        let config = test_config();
        let tokens = tokenize("gcloud auth application-default login");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_config_list_allowed() {
        let config = test_config();
        let tokens = tokenize("gcloud config list");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_projects_list_allowed() {
        let config = test_config();
        let tokens = tokenize("gcloud projects list");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_compute_instances_list_allowed() {
        let config = test_config();
        let tokens = tokenize("gcloud compute instances list");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_secrets_list_allowed() {
        let config = test_config();
        let tokens = tokenize("gcloud secrets list");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_secrets_versions_list_allowed() {
        let config = test_config();
        let tokens = tokenize("gcloud secrets versions list --secret=my-secret");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_sql_set_password_prompts_allowed() {
        let config = test_config();
        // Without --password flag, it prompts interactively (safer)
        let tokens = tokenize("gcloud sql users set-password root --instance=mydb");
        let decision = analyze_gcloud(&tokens, &config);
        assert!(!decision.is_blocked());
    }
}
