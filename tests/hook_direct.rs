use assert_cmd::cargo::cargo_bin_cmd;
use std::io::Write;
use tempfile::NamedTempFile;

const TEST_CONFIG: &str = r#"
sensitive_files = [
    '\.env\b',
    '\.envrc\b',
    'credentials',
    'secrets',
    '\.netrc\b',
    '\.npmrc\b',
    '\.pypirc\b',
    '\.pem\b',
    '\.key\b',
    'id_rsa',
    'id_ed25519',
    'id_ecdsa',
    '\.git-credentials',
    'kubeconfig',
    '\.aws/credentials',
    '_history\b',
    '\.bash_history',
    '\.zsh_history',
]

read_commands = '\b(cat|head|tail|less|more|grep|rg|ag|sed|awk|strings|xxd|hexdump|bat|view)\b'

[[deny]]
tool = "Bash"
pattern = '^\s*printenv'
reason = "Exposes environment variables"

[[deny]]
tool = "Bash"
pattern = '^\s*set\s*$'
reason = "Exposes shell variables"

[[deny]]
tool = "Bash"
pattern = '^\s*declare\s+-x'
reason = "Exposes exported variables"
"#;

fn cmd_with_config(config_file: &NamedTempFile) -> assert_cmd::Command {
    let mut cmd = cargo_bin_cmd!("aca-safety-net");
    cmd.env("ACO_SAFETY_NET_CONFIG", config_file.path());
    cmd
}

fn create_config() -> NamedTempFile {
    let mut f = NamedTempFile::new().unwrap();
    f.write_all(TEST_CONFIG.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

mod should_allow {
    use super::*;

    #[test]
    fn safe_ls() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"ls -la"}}"#)
            .assert()
            .code(0);
    }

    #[test]
    fn git_status() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#)
            .assert()
            .code(0);
    }

    #[test]
    fn read_normal_file() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(
                r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/src/main.rs"}}"#,
            )
            .assert()
            .code(0);
    }

    #[test]
    fn read_cargo_toml() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(
                r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/Cargo.toml"}}"#,
            )
            .assert()
            .code(0);
    }

    #[test]
    fn unknown_tool() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Write","tool_input":{"file_path":"/tmp/test"}}"#)
            .assert()
            .code(0);
    }

    #[test]
    fn invalid_json() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin("not valid json")
            .assert()
            .code(0);
    }

    #[test]
    fn empty_input() {
        let cfg = create_config();
        cmd_with_config(&cfg).write_stdin("").assert().code(0);
    }
}

mod should_block {
    use super::*;

    // Sensitive file reads via Bash
    #[test]
    fn cat_env() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"cat .env"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn cat_env_local() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"cat .env.local"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn cat_envrc() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"cat .envrc"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn grep_env() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"grep password .env"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn cat_ssh_key() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn cat_pem() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"cat server.pem"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn cat_aws_credentials() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(
                r#"{"tool_name":"Bash","tool_input":{"command":"cat ~/.aws/credentials"}}"#,
            )
            .assert()
            .code(2);
    }

    // Sensitive file reads via Read tool
    #[test]
    fn read_env() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/.env"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn read_env_local() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(
                r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/.env.local"}}"#,
            )
            .assert()
            .code(2);
    }

    #[test]
    fn read_ssh_key() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(
                r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/.ssh/id_rsa"}}"#,
            )
            .assert()
            .code(2);
    }

    #[test]
    fn read_ed25519() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(
                r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/.ssh/id_ed25519"}}"#,
            )
            .assert()
            .code(2);
    }

    #[test]
    fn read_pem() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(
                r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/certs/server.pem"}}"#,
            )
            .assert()
            .code(2);
    }

    #[test]
    fn read_aws_credentials() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(
                r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/.aws/credentials"}}"#,
            )
            .assert()
            .code(2);
    }

    #[test]
    fn read_netrc() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/.netrc"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn read_npmrc() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/.npmrc"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn read_bash_history() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(
                r#"{"tool_name":"Read","tool_input":{"file_path":"/home/user/.bash_history"}}"#,
            )
            .assert()
            .code(2);
    }

    // Environment exposure
    #[test]
    fn printenv() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"printenv"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn set_command() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"set"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn declare_x() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"declare -x"}}"#)
            .assert()
            .code(2);
    }

    // Git dangerous operations
    #[test]
    fn git_reset_hard() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(
                r#"{"tool_name":"Bash","tool_input":{"command":"git reset --hard HEAD~1"}}"#,
            )
            .assert()
            .code(2);
    }

    #[test]
    fn git_push_force_main() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(
                r#"{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}"#,
            )
            .assert()
            .code(2);
    }

    #[test]
    fn git_push_force_master() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(
                r#"{"tool_name":"Bash","tool_input":{"command":"git push -f origin master"}}"#,
            )
            .assert()
            .code(2);
    }

    #[test]
    fn git_checkout_discard() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(
                r#"{"tool_name":"Bash","tool_input":{"command":"git checkout -- src/main.rs"}}"#,
            )
            .assert()
            .code(2);
    }

    #[test]
    fn git_branch_delete() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"git branch -D feature"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn git_stash_drop() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"git stash drop"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn git_add_env() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"git add .env"}}"#)
            .assert()
            .code(2);
    }

    // Destructive rm
    #[test]
    fn rm_rf_root() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn rm_rf_home() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /home"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn rm_rf_parent() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf ../"}}"#)
            .assert()
            .code(2);
    }

    // find/xargs/parallel dangerous
    #[test]
    fn find_delete() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(
                r#"{"tool_name":"Bash","tool_input":{"command":"find . -name '*.tmp' -delete"}}"#,
            )
            .assert()
            .code(2);
    }

    #[test]
    fn find_exec_rm() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"find . -name '*.log' -exec rm {} \\;"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn xargs_rm() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"find . | xargs rm"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn parallel_rm() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"ls | parallel rm"}}"#)
            .assert()
            .code(2);
    }

    // Wrappers should be stripped
    #[test]
    fn sudo_cat_env() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"sudo cat .env"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn sudo_rm_rf_root() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"sudo rm -rf /"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn bash_c_cat_env() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"bash -c 'cat .env'"}}"#)
            .assert()
            .code(2);
    }

    // Chained commands
    #[test]
    fn chained_with_dangerous() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"ls && cat .env"}}"#)
            .assert()
            .code(2);
    }

    #[test]
    fn pipe_to_dangerous() {
        let cfg = create_config();
        cmd_with_config(&cfg)
            .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"echo test | cat .env"}}"#)
            .assert()
            .code(2);
    }
}
