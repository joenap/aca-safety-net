//! Integration tests for aca-safety-net binary.

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Helper to create a test config file.
fn create_config(dir: &TempDir, content: &str) -> std::path::PathBuf {
    let config_path = dir.path().join("security-hook.toml");
    fs::write(&config_path, content).unwrap();
    config_path
}

/// Get a command with config path set via env var.
fn cmd_with_config(config_path: &std::path::Path) -> assert_cmd::Command {
    let mut cmd = cargo_bin_cmd!("aca-safety-net");
    cmd.env("ACO_SAFETY_NET_CONFIG", config_path);
    cmd
}

/// Get a command with temp dir but no config (for fail-open tests).
fn cmd_without_config(home: &TempDir) -> assert_cmd::Command {
    let mut cmd = cargo_bin_cmd!("aca-safety-net");
    // Point to non-existent config
    cmd.env(
        "ACO_SAFETY_NET_CONFIG",
        home.path().join("nonexistent.toml"),
    );
    cmd
}

#[test]
fn test_allow_safe_command() {
    let dir = TempDir::new().unwrap();
    let config = create_config(
        &dir,
        r#"
sensitive_files = ['\.env\b']
read_commands = '\b(cat|head)\b'
"#,
    );

    let input = r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_block_cat_env() {
    let dir = TempDir::new().unwrap();
    let config = create_config(
        &dir,
        r#"
sensitive_files = ['\.env\b']
read_commands = '\b(cat|head)\b'
"#,
    );

    let input = r#"{"tool_name":"Bash","tool_input":{"command":"cat .env"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BLOCKED"));
}

#[test]
fn test_block_read_env() {
    let dir = TempDir::new().unwrap();
    let config = create_config(
        &dir,
        r#"
sensitive_files = ['\.env\b']
"#,
    );

    let input = r#"{"tool_name":"Read","tool_input":{"file_path":".env"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BLOCKED"));
}

#[test]
fn test_block_printenv() {
    let dir = TempDir::new().unwrap();
    let config = create_config(
        &dir,
        r#"
sensitive_files = []

[[deny]]
tool = "Bash"
pattern = '^printenv'
reason = "Exposes environment variables"
"#,
    );

    let input = r#"{"tool_name":"Bash","tool_input":{"command":"printenv PATH"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BLOCKED"));
}

#[test]
fn test_block_git_reset_hard() {
    let dir = TempDir::new().unwrap();
    let config = create_config(
        &dir,
        r#"
sensitive_files = []

[git]
block_destructive = true
"#,
    );

    let input = r#"{"tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~1"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BLOCKED"));
}

#[test]
fn test_block_rm_rf_root() {
    let dir = TempDir::new().unwrap();
    let config = create_config(
        &dir,
        r#"
sensitive_files = []

[rm]
block_outside_cwd = true
"#,
    );

    let input =
        r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"cwd":"/home/user/project"}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BLOCKED"));
}

#[test]
fn test_allow_rm_in_cwd() {
    let dir = TempDir::new().unwrap();
    let config = create_config(
        &dir,
        r#"
sensitive_files = []

[rm]
block_outside_cwd = true
"#,
    );

    let input = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf build/"},"cwd":"/home/user/project"}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .success();
}

#[test]
fn test_block_find_delete() {
    let dir = TempDir::new().unwrap();
    let config = create_config(&dir, r#"sensitive_files = []"#);

    let input = r#"{"tool_name":"Bash","tool_input":{"command":"find . -name '*.tmp' -delete"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BLOCKED"));
}

#[test]
fn test_block_xargs_rm() {
    let dir = TempDir::new().unwrap();
    let config = create_config(&dir, r#"sensitive_files = []"#);

    let input =
        r#"{"tool_name":"Bash","tool_input":{"command":"find . -name '*.log' | xargs rm"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BLOCKED"));
}

#[test]
fn test_paranoid_mode() {
    let dir = TempDir::new().unwrap();
    let config = create_config(
        &dir,
        r#"
sensitive_files = ['\.env\b']

[paranoid]
enabled = true
"#,
    );

    // Even ls .env should be blocked in paranoid mode
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"ls .env"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BLOCKED"));
}

#[test]
fn test_no_config_uses_hardcoded_defaults() {
    // No config file = hardcoded security defaults still apply
    let dir = TempDir::new().unwrap();

    // cat .env should be blocked by hardcoded defaults
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"cat .env"}}"#;

    cmd_without_config(&dir)
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BLOCKED"));
}

#[test]
fn test_no_config_allows_safe_commands() {
    // Safe commands should still be allowed with no config
    let dir = TempDir::new().unwrap();

    let input = r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#;

    cmd_without_config(&dir)
        .write_stdin(input)
        .assert()
        .success();
}

#[test]
fn test_invalid_json_allows() {
    let dir = TempDir::new().unwrap();
    let config = create_config(&dir, r#"sensitive_files = ['\.env\b']"#);

    // Invalid JSON = fail-open
    cmd_with_config(&config)
        .write_stdin("not valid json")
        .assert()
        .success();
}

#[test]
fn test_block_git_push_force_main() {
    let dir = TempDir::new().unwrap();
    let config = create_config(
        &dir,
        r#"
sensitive_files = []

[git]
block_destructive = true
force_push_allowed_branches = []
"#,
    );

    let input = r#"{"tool_name":"Bash","tool_input":{"command":"git push -f origin main"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BLOCKED"));
}

#[test]
fn test_allow_git_push_force_feature() {
    let dir = TempDir::new().unwrap();
    let config = create_config(
        &dir,
        r#"
sensitive_files = []

[git]
block_destructive = true
force_push_allowed_branches = []
"#,
    );

    // Force push to feature branch is allowed
    let input =
        r#"{"tool_name":"Bash","tool_input":{"command":"git push -f origin feature/my-branch"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .success();
}

#[test]
fn test_block_git_add_sensitive() {
    let dir = TempDir::new().unwrap();
    let config = create_config(
        &dir,
        r#"
sensitive_files = ['\.env\b']

[git]
block_add_sensitive = true
"#,
    );

    let input = r#"{"tool_name":"Bash","tool_input":{"command":"git add .env"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BLOCKED"));
}

#[test]
fn test_chained_command_block() {
    let dir = TempDir::new().unwrap();
    let config = create_config(
        &dir,
        r#"
sensitive_files = ['\.env\b']
read_commands = '\b(cat)\b'
"#,
    );

    // Second command in chain is blocked
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello && cat .env"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BLOCKED"));
}

#[test]
fn test_sudo_wrapper_stripped() {
    let dir = TempDir::new().unwrap();
    let config = create_config(
        &dir,
        r#"
sensitive_files = ['\.env\b']
read_commands = '\b(cat)\b'
"#,
    );

    // sudo is stripped, cat .env is blocked
    let input = r#"{"tool_name":"Bash","tool_input":{"command":"sudo cat .env"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("BLOCKED"));
}

#[test]
fn test_unknown_tool_allowed() {
    let dir = TempDir::new().unwrap();
    let config = create_config(&dir, r#"sensitive_files = ['\.env\b']"#);

    // Unknown tool passes through
    let input = r#"{"tool_name":"Write","tool_input":{"file_path":".env","content":"test"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .success();
}

#[test]
fn test_read_normal_file_allowed() {
    let dir = TempDir::new().unwrap();
    let config = create_config(&dir, r#"sensitive_files = ['\.env\b']"#);

    let input = r#"{"tool_name":"Read","tool_input":{"file_path":"src/main.rs"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .success();
}

#[test]
fn test_edit_cargo_toml_asks() {
    let dir = TempDir::new().unwrap();
    let config = create_config(&dir, r#"sensitive_files = []"#);

    let input = r#"{"tool_name":"Edit","tool_input":{"file_path":"Cargo.toml","old_string":"old","new_string":"new"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"permissionDecision\":\"ask\""))
        .stdout(predicate::str::contains("cargo add"));
}

#[test]
fn test_write_package_json_asks() {
    let dir = TempDir::new().unwrap();
    let config = create_config(&dir, r#"sensitive_files = []"#);

    let input = r#"{"tool_name":"Write","tool_input":{"file_path":"package.json","content":"{}"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"permissionDecision\":\"ask\""));
}

#[test]
fn test_edit_normal_file_allowed() {
    let dir = TempDir::new().unwrap();
    let config = create_config(&dir, r#"sensitive_files = []"#);

    let input = r#"{"tool_name":"Edit","tool_input":{"file_path":"src/main.rs","old_string":"old","new_string":"new"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_edit_deps_disabled_allows() {
    let dir = TempDir::new().unwrap();
    let config = create_config(
        &dir,
        r#"
sensitive_files = []

[dependencies]
enabled = false
"#,
    );

    let input = r#"{"tool_name":"Edit","tool_input":{"file_path":"Cargo.toml","old_string":"old","new_string":"new"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_edit_pyproject_toml_asks() {
    let dir = TempDir::new().unwrap();
    let config = create_config(&dir, r#"sensitive_files = []"#);

    let input = r#"{"tool_name":"Edit","tool_input":{"file_path":"/home/user/project/pyproject.toml","old_string":"old","new_string":"new"}}"#;

    cmd_with_config(&config)
        .write_stdin(input)
        .assert()
        .success()
        .stdout(predicate::str::contains("\"permissionDecision\":\"ask\""))
        .stdout(predicate::str::contains("uv add"));
}
