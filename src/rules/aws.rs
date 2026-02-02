//! AWS CLI analysis - blocks commands that expose secrets.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Analyze AWS CLI commands for secret exposure.
pub fn analyze_aws(tokens: &[Token], _config: &CompiledConfig) -> Decision {
    let words: Vec<&str> = tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect();

    if words.len() < 3 {
        return Decision::allow();
    }

    // AWS CLI structure: aws <service> <command> [options]
    let service = words[1];
    let command = words[2];

    match service {
        // Secrets Manager - always blocks secret retrieval
        "secretsmanager" => match command {
            "get-secret-value" => Decision::block(
                "aws.secretsmanager.get",
                "aws secretsmanager get-secret-value exposes secret contents",
            ),
            _ => Decision::allow(),
        },

        // SSM Parameter Store
        "ssm" => match command {
            "get-parameter" | "get-parameters" | "get-parameters-by-path" => {
                // Only block if --with-decryption is present
                if words.contains(&"--with-decryption") {
                    Decision::block(
                        "aws.ssm.decrypt",
                        "aws ssm get-parameter with --with-decryption exposes decrypted secrets",
                    )
                } else {
                    Decision::allow()
                }
            }
            _ => Decision::allow(),
        },

        // KMS - decryption exposes plaintext
        "kms" => match command {
            "decrypt" => {
                Decision::block("aws.kms.decrypt", "aws kms decrypt exposes decrypted data")
            }
            _ => Decision::allow(),
        },

        // IAM - access key enumeration
        "iam" => match command {
            "list-access-keys" => Decision::block(
                "aws.iam.keys",
                "aws iam list-access-keys exposes access key IDs",
            ),
            "get-access-key-last-used" => Decision::block(
                "aws.iam.keys",
                "aws iam get-access-key-last-used exposes access key information",
            ),
            "create-access-key" => Decision::block(
                "aws.iam.keys",
                "aws iam create-access-key creates and exposes new credentials",
            ),
            _ => Decision::allow(),
        },

        // STS - session token generation
        "sts" => match command {
            "get-session-token" => Decision::block(
                "aws.sts.credentials",
                "aws sts get-session-token exposes temporary credentials",
            ),
            "assume-role" => Decision::block(
                "aws.sts.credentials",
                "aws sts assume-role exposes temporary credentials",
            ),
            _ => Decision::allow(),
        },

        // Configure - credential export
        "configure" => match command {
            "export-credentials" => Decision::block(
                "aws.configure.export",
                "aws configure export-credentials exposes credentials",
            ),
            _ => Decision::allow(),
        },

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
    fn test_secretsmanager_get_secret() {
        let config = test_config();
        let tokens = tokenize("aws secretsmanager get-secret-value --secret-id my-secret");
        let decision = analyze_aws(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_ssm_get_parameter_with_decryption() {
        let config = test_config();
        let tokens = tokenize("aws ssm get-parameter --name /path/to/secret --with-decryption");
        let decision = analyze_aws(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_ssm_get_parameters_with_decryption() {
        let config = test_config();
        let tokens = tokenize("aws ssm get-parameters --names /a /b --with-decryption");
        let decision = analyze_aws(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_ssm_get_parameters_by_path_with_decryption() {
        let config = test_config();
        let tokens = tokenize("aws ssm get-parameters-by-path --path /app --with-decryption");
        let decision = analyze_aws(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_kms_decrypt() {
        let config = test_config();
        let tokens = tokenize("aws kms decrypt --ciphertext-blob fileb://encrypted.txt");
        let decision = analyze_aws(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_iam_list_access_keys() {
        let config = test_config();
        let tokens = tokenize("aws iam list-access-keys --user-name alice");
        let decision = analyze_aws(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_iam_create_access_key() {
        let config = test_config();
        let tokens = tokenize("aws iam create-access-key --user-name alice");
        let decision = analyze_aws(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_sts_get_session_token() {
        let config = test_config();
        let tokens = tokenize("aws sts get-session-token");
        let decision = analyze_aws(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_sts_assume_role() {
        let config = test_config();
        let tokens = tokenize("aws sts assume-role --role-arn arn:aws:iam::123:role/Admin");
        let decision = analyze_aws(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_configure_export_credentials() {
        let config = test_config();
        let tokens = tokenize("aws configure export-credentials");
        let decision = analyze_aws(&tokens, &config);
        assert!(decision.is_blocked());
    }

    // Allowed commands

    #[test]
    fn test_ssm_get_parameter_without_decryption() {
        let config = test_config();
        let tokens = tokenize("aws ssm get-parameter --name /path/to/param");
        let decision = analyze_aws(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_s3_ls_allowed() {
        let config = test_config();
        let tokens = tokenize("aws s3 ls s3://my-bucket");
        let decision = analyze_aws(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_ec2_describe_instances_allowed() {
        let config = test_config();
        let tokens = tokenize("aws ec2 describe-instances");
        let decision = analyze_aws(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_sts_get_caller_identity_allowed() {
        let config = test_config();
        let tokens = tokenize("aws sts get-caller-identity");
        let decision = analyze_aws(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_configure_list_allowed() {
        let config = test_config();
        let tokens = tokenize("aws configure list");
        let decision = analyze_aws(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_secretsmanager_list_allowed() {
        let config = test_config();
        let tokens = tokenize("aws secretsmanager list-secrets");
        let decision = analyze_aws(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_iam_list_users_allowed() {
        let config = test_config();
        let tokens = tokenize("aws iam list-users");
        let decision = analyze_aws(&tokens, &config);
        assert!(!decision.is_blocked());
    }
}
