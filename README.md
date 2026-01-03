# ACA Safety Net

> **Note:** This project is a hard fork of [claude-code-safety-net](https://github.com/kenryu42/claude-code-safety-net) by kenryu42. Full attribution goes to the original project. This is a Claude-driven rewrite in Rust with additional features including cloud CLI protection (Heroku, AWS, GCloud), enhanced shell parsing, and configurable rule systems.

A Rust-based security hook for Claude Code that blocks access to sensitive files, dangerous commands, and environment variable exposure.

## Features

- **Fast**: <5ms execution (vs 50-100ms for Python alternatives)
- **Secrets Protection**: Blocks read access to `.env`, credentials, SSH keys, API tokens
- **Cloud CLI Protection**: Blocks secret-exposing commands from Heroku, AWS, and GCloud CLIs
- **Destructive Command Detection**: Blocks `rm -rf` outside working directory, dangerous git operations
- **Shell-Aware**: Parses command chains (`&&`, `||`, `|`, `;`), strips wrappers (`sudo`, `env`, `bash -c`)
- **Configurable**: TOML config with user + project-level overrides
- **Paranoid Mode**: Optional strict mode that blocks ANY mention of sensitive files

## Quick Start

### 1. Build and Install

```bash
just install
# Installs binary to ~/.local/bin/ and config to ~/.claude/
# Ensure ~/.local/bin is in your PATH
```

### 2. Configure Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read",
        "hooks": [
          {
            "type": "command",
            "command": "aca-safety-net",
            "timeout": 1
          }
        ]
      }
    ]
  }
}
```

## Configuration

Configuration files are loaded and merged in order:

1. `~/.claude/security-hook.toml` (user-level, global)
2. `.security-hook.toml` (project-level, in cwd)

Project config extends and overrides user config.

### Example Config

```toml
# Sensitive file patterns (regex)
sensitive_files = [
    '\\.env\\b',
    '\\.envrc\\b',
    'credentials',
    'secrets',
    '\\.pem$',
    '\\.key$',
    'id_rsa',
    'id_ed25519',
    '\\.aws/credentials',
    '\\.config/gcloud/',
]

# Commands that read file content
read_commands = '\\b(cat|head|tail|less|more|grep|rg|sed|awk|strings|xxd)\\b'

# Explicit deny rules
[[deny]]
tool = "Bash"
pattern = '^\\s*printenv'
reason = "Exposes environment variables"

[[deny]]
tool = "Bash"
pattern = '/proc/.*/environ'
reason = "Exposes process environment"

# Git settings
[git]
block_destructive = true
block_add_sensitive = true
force_push_allowed_branches = []  # Empty = block all force pushes to protected branches

# rm settings
[rm]
block_outside_cwd = true
allowed_paths = ["/tmp", "/var/tmp"]

# Paranoid mode (optional)
[paranoid]
enabled = false
extra_patterns = []

# Audit logging (optional)
[audit]
enabled = false
path = "~/.claude/security-hook.log"
```

## What Gets Blocked

### Sensitive Files (Read + Bash)

- `.env`, `.envrc`, `.env.local`, `.env.production`
- SSH keys: `id_rsa`, `id_ed25519`, `id_ecdsa`
- Credentials: `.aws/credentials`, `.config/gcloud/`, `.netrc`, `.npmrc`
- Certificates: `*.pem`, `*.key`
- History files: `.bash_history`, `.zsh_history`

### Environment Exposure (Bash)

- `printenv`, `set`, `export`, `declare -x`
- `/proc/*/environ`
- `ps auxe`, `ps -E`
- `docker inspect`, `docker exec ... env`

### Destructive Git Operations

- `git checkout --` (discards changes)
- `git reset --hard` (discards all uncommitted changes)
- `git push -f` to main/master/develop/release
- `git branch -D` (force delete)
- `git stash drop`, `git stash clear`
- `git clean -f`
- `git add .env` (blocks staging sensitive files)

### Dangerous rm Operations

- `rm -rf /` or system directories (`/home`, `/etc`, `/usr`, etc.)
- `rm -rf` outside current working directory
- `rm -rf ../../..` (parent traversal)
- Allowed: `rm -rf` in cwd or `/tmp`

### Dangerous find/xargs/parallel

- `find -delete`
- `find -exec rm`
- `xargs rm`
- `parallel rm`

### Cloud CLI Secret Exposure

#### Heroku
- `heroku auth:token` (exposes auth token)
- `heroku config` / `heroku config:get` (exposes env vars)
- `heroku pg:credentials` / `heroku redis:credentials` (database credentials)

#### AWS
- `aws secretsmanager get-secret-value` (retrieves secrets)
- `aws ssm get-parameter --with-decryption` (decrypts parameters)
- `aws kms decrypt` (decrypts data)
- `aws iam list-access-keys` / `aws iam create-access-key` (access key exposure)
- `aws sts get-session-token` / `aws sts assume-role` (temporary credentials)
- `aws configure export-credentials` (exports credentials)

#### GCloud
- `gcloud auth print-access-token` / `gcloud auth print-identity-token` (token exposure)
- `gcloud auth application-default print-access-token` (ADC token)
- `gcloud secrets versions access` (retrieves secret values)

**Allowed**: Non-secret queries like `aws s3 ls`, `gcloud config list`, `heroku apps`

## Paranoid Mode

Enable paranoid mode to block ANY command that mentions sensitive files, not just read commands:

```toml
[paranoid]
enabled = true
extra_patterns = [
    'secret',
    'password',
]
```

With paranoid mode enabled, even `ls .env` or `echo ".env created"` will be blocked.

## Custom Rules

Add custom rules to block or allow specific patterns:

```toml
[[rules]]
name = "block_curl_upload"
tool = "Bash"
pattern = 'curl.*-d\\s+@'
action = "block"
reason = "Blocks curl file uploads"

[[rules]]
name = "allow_safe_api"
tool = "Bash"
pattern = 'curl.*api\\.example\\.com'
action = "allow"
```

## How It Works

1. Claude Code invokes the hook via stdin (JSON with `tool_name`, `tool_input`)
2. Hook loads config from `~/.claude/security-hook.toml` + `.security-hook.toml`
3. For Bash: parses command, strips wrappers, checks deny rules + sensitive patterns
4. For Read: checks file path against sensitive patterns
5. Exit 0 = allow, Exit 2 = block (message shown to Claude)

### Fail-Open Design

The hook fails open (allows) on:
- Stdin read errors
- JSON parse errors
- Missing config file
- Invalid regex patterns

This prevents the hook from breaking Claude Code if misconfigured.

## Architecture

```
stdin JSON → Parse HookInput → Load Config
                                    ↓
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
               Bash Tool                       Read Tool
                    │                               │
      1. Check deny rules              1. Check deny rules
      2. Paranoid mode check           2. Sensitive patterns
      3. Read cmd + sensitive          3. Decision
      4. Git add sensitive                     ↓
      5. Split commands              Allow or Block
      6. Analyze segments
            │
      ┌─────┴─────┐
      ▼           ▼
   git/rm/    Recursive
   find/xargs  bash -c
```

## Known Limitations

Cannot detect or prevent:
- Variable expansion: `rm -rf $VAR`
- Symlink traversal
- Indirect file access: `python -c "open('.env')"`
- Network exfiltration: `curl -d @.env`
- Shell aliases
- Encoded/obfuscated commands

This is static analysis only - it cannot execute commands to determine their actual behavior.

## Development

```bash
just test      # Run tests
just release   # Build release
just install   # Build and install
just ci        # Full CI check (fmt, lint, test)
```

### Project Structure

```
src/
├── main.rs           # Entry point
├── lib.rs            # Library exports
├── config.rs         # TOML config loading
├── input.rs          # Hook input parsing
├── decision.rs       # Allow/Block types
├── audit.rs          # JSONL logging
├── shell/            # Shell parsing
│   ├── splitter.rs   # Command splitting
│   ├── tokenizer.rs  # Token parsing
│   └── wrappers.rs   # Wrapper stripping
├── analysis/         # Tool analysis
│   ├── bash.rs
│   └── read.rs
├── rules/            # Built-in rules
│   ├── git.rs
│   ├── rm.rs
│   ├── find.rs
│   ├── xargs.rs
│   ├── parallel.rs
│   ├── secrets.rs
│   ├── heroku.rs     # Heroku CLI
│   ├── aws.rs        # AWS CLI
│   ├── gcloud.rs     # GCloud CLI
│   └── custom.rs
└── output/           # Response formatting
    ├── response.rs
    └── redaction.rs
```

## License

MIT
