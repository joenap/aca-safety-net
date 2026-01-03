//! Built-in and custom rules for command analysis.

mod custom;
mod find;
mod git;
mod parallel;
mod rm;
mod secrets;
mod xargs;

pub use custom::check_custom_rules;
pub use find::analyze_find;
pub use git::analyze_git;
pub use parallel::analyze_parallel;
pub use rm::analyze_rm;
pub use secrets::{check_sensitive_path, check_git_add_sensitive};
pub use xargs::analyze_xargs;

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::{split_commands, strip_wrappers, tokenize, Token};

/// Analyze a command and return a decision.
pub fn analyze_command(command: &str, config: &CompiledConfig, cwd: Option<&str>) -> Decision {
    // Split command on operators
    let segments = split_commands(command);

    for segment in &segments {
        // Strip wrappers to get actual command
        let stripped = strip_wrappers(&segment.command);
        let tokens = tokenize(&stripped);

        // Get command name
        let cmd_name = tokens.iter().find_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        });

        let Some(cmd_name) = cmd_name else {
            continue;
        };

        // Check built-in rules based on command
        let decision = match cmd_name {
            "git" => analyze_git(&tokens, config),
            "rm" => analyze_rm(&tokens, config, cwd),
            "find" => analyze_find(&tokens, config),
            "xargs" => analyze_xargs(&tokens, config),
            "parallel" => analyze_parallel(&tokens, config),
            _ => Decision::Allow,
        };

        if decision.is_blocked() {
            return decision;
        }
    }

    Decision::Allow
}
