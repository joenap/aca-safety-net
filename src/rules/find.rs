//! find command analysis.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Analyze find command for dangerous operations.
pub fn analyze_find(tokens: &[Token], _config: &CompiledConfig) -> Decision {
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

    // Check for -delete action
    if words.contains(&"-delete") {
        return Decision::block(
            "find.delete",
            "find -delete permanently deletes matching files",
        );
    }

    // Check for -exec with rm
    let mut in_exec = false;
    let mut exec_has_rm = false;

    for word in &words {
        if *word == "-exec" || *word == "-execdir" {
            in_exec = true;
            continue;
        }

        if in_exec {
            if *word == ";" || *word == "+" || *word == "\\;" {
                in_exec = false;
                if exec_has_rm {
                    return Decision::block(
                        "find.exec_rm",
                        "find -exec rm permanently deletes matching files",
                    );
                }
                exec_has_rm = false;
            } else if *word == "rm" || word.ends_with("/rm") {
                exec_has_rm = true;
            }
        }
    }

    // Check for -ok with rm (interactive, but still flag it)
    let mut in_ok = false;
    for word in &words {
        if *word == "-ok" || *word == "-okdir" {
            in_ok = true;
            continue;
        }

        if in_ok {
            if *word == ";" || *word == "\\;" {
                in_ok = false;
            } else if *word == "rm" || word.ends_with("/rm") {
                return Decision::block(
                    "find.ok_rm",
                    "find -ok rm can delete matching files (interactive)",
                );
            }
        }
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
    fn test_find_delete() {
        let config = test_config();
        let tokens = tokenize("find . -name '*.tmp' -delete");
        let decision = analyze_find(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_find_exec_rm() {
        let config = test_config();
        let tokens = tokenize("find . -name '*.log' -exec rm {} ;");
        let decision = analyze_find(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_find_exec_rm_plus() {
        let config = test_config();
        let tokens = tokenize("find . -name '*.log' -exec rm {} +");
        let decision = analyze_find(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_find_execdir_rm() {
        let config = test_config();
        let tokens = tokenize("find . -name '*.tmp' -execdir rm {} ;");
        let decision = analyze_find(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_find_ok_rm() {
        let config = test_config();
        let tokens = tokenize("find . -name '*.tmp' -ok rm {} ;");
        let decision = analyze_find(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_find_safe() {
        let config = test_config();
        let tokens = tokenize("find . -name '*.rs' -print");
        let decision = analyze_find(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_find_exec_cat() {
        let config = test_config();
        let tokens = tokenize("find . -name '*.txt' -exec cat {} ;");
        let decision = analyze_find(&tokens, &config);
        assert!(!decision.is_blocked());
    }
}
