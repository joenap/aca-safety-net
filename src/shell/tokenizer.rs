//! Shell-style tokenization (shlex-like).

/// A token from shell parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// A regular word/argument.
    Word(String),
    /// A redirection operator (>, >>, <, etc.).
    Redirect(String),
    /// An assignment (VAR=value).
    Assignment(String, String),
}

/// Tokenize a shell command into words, respecting quotes and escapes.
pub fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape_next = false;

    while let Some(c) = chars.next() {
        if escape_next {
            current.push(c);
            escape_next = false;
            continue;
        }

        if c == '\\' && !in_single_quote {
            escape_next = true;
            // In double quotes, only certain chars are escaped
            if !in_double_quote {
                continue; // Don't include the backslash
            }
            current.push(c);
            continue;
        }

        if c == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            continue; // Don't include the quote
        }

        if c == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            continue; // Don't include the quote
        }

        if in_single_quote || in_double_quote {
            current.push(c);
            continue;
        }

        // Outside quotes
        if c.is_whitespace() {
            if !current.is_empty() {
                tokens.push(classify_token(&current));
                current.clear();
            }
            continue;
        }

        // Check for redirections
        if c == '>' || c == '<' {
            if !current.is_empty() {
                tokens.push(classify_token(&current));
                current.clear();
            }
            let mut redir = String::from(c);
            if c == '>' && chars.peek() == Some(&'>') {
                redir.push(chars.next().unwrap());
            }
            if c == '>' && chars.peek() == Some(&'&') {
                redir.push(chars.next().unwrap());
            }
            if c == '<' && chars.peek() == Some(&'<') {
                redir.push(chars.next().unwrap());
                if chars.peek() == Some(&'<') {
                    redir.push(chars.next().unwrap());
                }
            }
            tokens.push(Token::Redirect(redir));
            continue;
        }

        current.push(c);
    }

    if !current.is_empty() {
        tokens.push(classify_token(&current));
    }

    tokens
}

fn classify_token(s: &str) -> Token {
    // Check for assignment (VAR=value, not starting with =)
    if let Some(eq_pos) = s.find('=') {
        if eq_pos > 0 {
            let var = &s[..eq_pos];
            // Variable names must be valid identifiers
            if is_valid_var_name(var) {
                let value = &s[eq_pos + 1..];
                return Token::Assignment(var.to_string(), value.to_string());
            }
        }
    }
    Token::Word(s.to_string())
}

fn is_valid_var_name(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_alphanumeric() || c == '_')
}

/// Get the command name (first word) from tokens.
#[allow(dead_code)]
pub fn command_name(tokens: &[Token]) -> Option<&str> {
    for token in tokens {
        match token {
            Token::Word(w) => return Some(w),
            Token::Assignment(_, _) => continue, // Skip env assignments
            Token::Redirect(_) => continue,
        }
    }
    None
}

/// Get all arguments after the command name.
#[allow(dead_code)]
pub fn arguments(tokens: &[Token]) -> Vec<&str> {
    let mut args = Vec::new();
    let mut found_command = false;
    for token in tokens {
        match token {
            Token::Word(w) => {
                if found_command {
                    args.push(w.as_str());
                } else {
                    found_command = true;
                }
            }
            Token::Assignment(_, _) => {}
            Token::Redirect(_) => {}
        }
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_tokenize() {
        let tokens = tokenize("ls -la /tmp");
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0], Token::Word("ls".to_string()));
        assert_eq!(tokens[1], Token::Word("-la".to_string()));
    }

    #[test]
    fn test_quoted_string() {
        let tokens = tokenize("echo 'hello world'");
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[1], Token::Word("hello world".to_string()));
    }

    #[test]
    fn test_double_quoted() {
        let tokens = tokenize("echo \"hello world\"");
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[1], Token::Word("hello world".to_string()));
    }

    #[test]
    fn test_escaped_space() {
        let tokens = tokenize("echo hello\\ world");
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[1], Token::Word("hello world".to_string()));
    }

    #[test]
    fn test_assignment() {
        let tokens = tokenize("FOO=bar echo $FOO");
        assert_eq!(tokens.len(), 3);
        assert_eq!(
            tokens[0],
            Token::Assignment("FOO".to_string(), "bar".to_string())
        );
    }

    #[test]
    fn test_redirect() {
        let tokens = tokenize("cat file > output");
        assert_eq!(tokens.len(), 4);
        assert_eq!(tokens[2], Token::Redirect(">".to_string()));
    }

    #[test]
    fn test_append_redirect() {
        let tokens = tokenize("echo hello >> file");
        assert!(tokens.iter().any(|t| *t == Token::Redirect(">>".to_string())));
    }

    #[test]
    fn test_command_name() {
        let tokens = tokenize("FOO=bar sudo ls -la");
        assert_eq!(command_name(&tokens), Some("sudo"));
    }

    #[test]
    fn test_arguments() {
        let tokens = tokenize("git commit -m 'message'");
        let args = arguments(&tokens);
        assert_eq!(args, vec!["commit", "-m", "message"]);
    }
}
