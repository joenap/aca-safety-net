//! GNU parallel command analysis.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Analyze parallel command for dangerous operations.
pub fn analyze_parallel(tokens: &[Token], _config: &CompiledConfig) -> Decision {
    let words: Vec<&str> = tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect();

    if words.is_empty() {
        return Decision::allow();
    }

    // Look for rm in the command
    // parallel can have complex command structures, so we look for rm anywhere
    let mut found_rm = false;
    let mut has_recursive = false;

    for word in &words[1..] {
        if *word == "rm" || word.ends_with("/rm") {
            found_rm = true;
        }

        if *word == "-r"
            || *word == "-R"
            || *word == "--recursive"
            || *word == "-rf"
            || *word == "-fr"
        {
            has_recursive = true;
        }

        // Check combined options
        if word.starts_with('-') && !word.starts_with("--") {
            if word.contains('r') || word.contains('R') {
                has_recursive = true;
            }
        }
    }

    if found_rm {
        if has_recursive {
            return Decision::block(
                "parallel.rm_rf",
                "parallel rm -rf is dangerous - deletes files in parallel from input",
            );
        }
        return Decision::block(
            "parallel.rm",
            "parallel rm is dangerous - deletes files in parallel from input",
        );
    }

    Decision::allow()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::shell::tokenize;

    fn test_config() -> CompiledConfig {
        Config::default().compile().unwrap()
    }

    #[test]
    fn test_parallel_rm() {
        let config = test_config();
        let tokens = tokenize("parallel rm {}");
        let decision = analyze_parallel(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_parallel_rm_rf() {
        let config = test_config();
        let tokens = tokenize("parallel rm -rf {}");
        let decision = analyze_parallel(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_parallel_echo() {
        let config = test_config();
        let tokens = tokenize("parallel echo {}");
        let decision = analyze_parallel(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_parallel_gzip() {
        let config = test_config();
        let tokens = tokenize("parallel gzip {}");
        let decision = analyze_parallel(&tokens, &config);
        assert!(!decision.is_blocked());
    }
}
