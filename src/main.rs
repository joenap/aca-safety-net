//! ACO Safety Net - Claude Code security hook entry point.

use aco_safety_net::analysis::{analyze_bash, analyze_read};
use aco_safety_net::audit::AuditLogger;
use aco_safety_net::config::Config;
use aco_safety_net::decision::Decision;
use aco_safety_net::input::HookInput;
use aco_safety_net::output::format_response;

use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    // Read JSON from stdin
    let mut input_str = String::new();
    if io::stdin().read_to_string(&mut input_str).is_err() {
        return ExitCode::SUCCESS; // Fail-open on read error
    }

    // Parse input
    let hook_input = match HookInput::parse(&input_str) {
        Ok(v) => v,
        Err(_) => return ExitCode::SUCCESS, // Fail-open on parse error
    };

    // Load config
    let cwd = hook_input.cwd.as_deref().map(Path::new);
    let config = match Config::load(cwd) {
        Ok(c) => c,
        Err(_) => return ExitCode::SUCCESS, // Fail-open if no config
    };

    // Compile config patterns
    let compiled = match config.compile() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Config error: {}", e);
            return ExitCode::SUCCESS; // Fail-open on config error
        }
    };

    // Analyze based on tool type
    let decision = match hook_input.tool_name.as_str() {
        "Bash" => {
            if let Some(bash_input) = hook_input.as_bash() {
                analyze_bash(&bash_input, &compiled, hook_input.cwd.as_deref())
            } else {
                Decision::allow()
            }
        }
        "Read" => {
            if let Some(read_input) = hook_input.as_read() {
                analyze_read(&read_input, &compiled)
            } else {
                Decision::allow()
            }
        }
        // Other tools pass through (for now)
        _ => Decision::allow(),
    };

    // Audit logging (if enabled)
    if compiled.raw.audit.enabled {
        if let Some(path) = &compiled.raw.audit.path {
            if let Ok(mut logger) = AuditLogger::open(Path::new(path)) {
                let _ = logger.log_decision(&hook_input, &decision);
            }
        }
    }

    // Output result
    match &decision {
        Decision::Allow => ExitCode::SUCCESS,
        Decision::Block(_) => {
            if let Some(msg) = format_response(&decision) {
                eprintln!("{}", msg);
            }
            ExitCode::from(2)
        }
    }
}
