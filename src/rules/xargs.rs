//! xargs command analysis.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Analyze xargs command for dangerous operations.
pub fn analyze_xargs(tokens: &[Token], _config: &CompiledConfig) -> Decision {
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

    // Find the command being executed by xargs
    // Skip xargs options to find the actual command
    let mut i = 1;
    while i < words.len() {
        let word = words[i];

        // Skip xargs options
        if word.starts_with('-') {
            // Options that take arguments
            if matches!(
                word,
                "-I" | "-L"
                    | "-n"
                    | "-P"
                    | "-s"
                    | "-a"
                    | "-E"
                    | "-d"
                    | "--delimiter"
                    | "--max-args"
                    | "--max-procs"
                    | "--replace"
                    | "--max-lines"
                    | "--arg-file"
                    | "--eof"
                    | "--max-chars"
            ) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        // This is the command
        if word == "rm" || word.ends_with("/rm") {
            // Check if it's rm -rf or rm -r
            let remaining = &words[i..];
            let has_recursive = remaining.iter().any(|w| {
                *w == "-r"
                    || *w == "-R"
                    || *w == "--recursive"
                    || (w.starts_with('-') && !w.starts_with("--") && (w.contains('r') || w.contains('R')))
            });

            if has_recursive {
                return Decision::block(
                    "xargs.rm_rf",
                    "xargs rm -rf is dangerous - deletes files from piped input",
                );
            }

            return Decision::block(
                "xargs.rm",
                "xargs rm is dangerous - deletes files from piped input",
            );
        }

        break;
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
    fn test_xargs_rm() {
        let config = test_config();
        let tokens = tokenize("xargs rm");
        let decision = analyze_xargs(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_xargs_rm_rf() {
        let config = test_config();
        let tokens = tokenize("xargs rm -rf");
        let decision = analyze_xargs(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_xargs_with_options_rm() {
        let config = test_config();
        let tokens = tokenize("xargs -I {} rm {}");
        let decision = analyze_xargs(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_xargs_cat() {
        let config = test_config();
        let tokens = tokenize("xargs cat");
        let decision = analyze_xargs(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_xargs_echo() {
        let config = test_config();
        let tokens = tokenize("xargs -I {} echo {}");
        let decision = analyze_xargs(&tokens, &config);
        assert!(!decision.is_blocked());
    }
}
