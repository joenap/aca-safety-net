# ACO Safety Net: Rust Security Hook Implementation Plan

## Overview

Reimplement `claude-code-safety-net` (Python) in Rust with enhanced secrets protection. Target <5ms execution vs Python's 50-100ms.

## Scope

### Port from Python Project
- Shell command splitting (`&&`, `||`, `|`, `;`, `&`)
- Wrapper stripping (`sudo`, `env`, `bash -c` up to 5 levels)
- Git analysis: `checkout --`, `reset --hard`, `push --force`, `branch -D`, `stash drop/clear`
- rm analysis: block `rm -rf` outside cwd/tmp
- find/xargs/parallel with `rm -rf` detection
- Custom rules (user + project scope)
- Secret redaction in output
- Audit logging

### New Secrets Protection
- Hook **Read tool** (not just Bash)
- Block read commands (cat, grep, etc.) on sensitive files
- Block `git add` on .env/credentials/keys
- **Paranoid mode**: block ANY mention of sensitive files

## Module Structure

```
src/
├── main.rs           # Entry point, stdin/stdout
├── lib.rs            # For testing
├── config.rs         # TOML loading, user+project merge
├── input.rs          # HookInput parsing
├── decision.rs       # Allow/Block types, JSON output
├── shell/
│   ├── mod.rs
│   ├── splitter.rs   # Split on operators
│   ├── tokenizer.rs  # shlex-style
│   └── wrappers.rs   # Strip sudo/env/bash -c
├── analysis/
│   ├── mod.rs
│   ├── bash.rs       # Bash tool analysis
│   └── read.rs       # Read tool analysis
├── rules/
│   ├── mod.rs
│   ├── git.rs        # Git semantic analysis
│   ├── rm.rs         # rm -rf analysis
│   ├── find.rs       # find -delete/-exec
│   ├── xargs.rs      # xargs rm
│   ├── parallel.rs   # parallel rm
│   ├── secrets.rs    # Sensitive file patterns
│   └── custom.rs     # User-defined rules
├── output/
│   ├── mod.rs
│   ├── response.rs   # JSON response
│   └── redaction.rs  # Secret redaction
└── audit.rs          # JSONL logging
```

## Key Data Structures

```rust
#[derive(Deserialize)]
pub struct HookInput {
    pub tool_name: String,
    pub tool_input: serde_json::Value,
    pub cwd: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Deserialize)]
pub struct Config {
    pub sensitive_files: Vec<String>,      // Regex patterns
    pub read_commands: Option<String>,     // Regex for cat/grep/etc.
    pub deny: Vec<DenyRule>,               // Explicit blocks
    pub rules: Vec<CustomRule>,            // User-defined
    pub paranoid: ParanoidConfig,
}

pub enum Decision {
    Allow,
    Block(BlockInfo),
}
```

## Analysis Pipeline

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
      5. Split commands              Allow or Block JSON
      6. Analyze segments
            │
      ┌─────┴─────┐
      ▼           ▼
   git/rm/    Recursive
   find/xargs  bash -c
```

## Dependencies

Already added:
- `serde`, `serde_json`, `toml`, `regex`, `dirs`

To add:
```bash
cargo add once_cell thiserror chrono
cargo add --dev tempfile assert_cmd predicates
```

## Config Files

| File | Scope |
|------|-------|
| `~/.claude/security-hook.toml` | User (global) |
| `.security-hook.toml` | Project (cwd, merges with user) |

## Installation (Manual)

1. Build: `cargo build --release`
2. Install: `cp target/release/aco-safety-net ~/.local/bin/`
3. Config: `cp config.toml ~/.claude/security-hook.toml`
4. Edit `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash|Read",
      "hooks": [{
        "type": "command",
        "command": "aco-safety-net",
        "timeout": 1
      }]
    }]
  }
}
```

## Implementation Phases

### Phase 1: Core Infrastructure
- [ ] Project structure (modules)
- [ ] Config loading (user + project merge)
- [ ] Input parsing (HookInput, BashInput, ReadInput)
- [ ] Decision types and JSON output

### Phase 2: Shell Parsing (port from Python)
- [ ] Command splitter (operators)
- [ ] Tokenizer (shlex-style)
- [ ] Wrapper stripping
- [ ] Option extraction

### Phase 3: Built-in Rules (port from Python)
- [ ] Git analysis (all subcommands)
- [ ] rm analysis (cwd-aware paths)
- [ ] find/xargs/parallel detection

### Phase 4: Secrets Protection (new)
- [ ] Read tool handler
- [ ] Sensitive file patterns
- [ ] Paranoid mode
- [ ] Git add blocking

### Phase 5: Polish
- [ ] Secret redaction
- [ ] Audit logging
- [ ] Custom rules
- [ ] Unit + integration tests (90% coverage)
- [ ] README with docs

## Known Limitations

**Cannot solve:**
- Variable expansion (`rm -rf $VAR`)
- Symlink detection
- Indirect access (`python -c "open('.env')"`)
- Network exfil (`curl -d @.env`)
- Shell aliases

**Tradeoffs:**
- Static analysis only (for speed)
- Fail-open default (strict mode available)
- TOML config (readable, comments)

## Critical Files to Modify

- `src/main.rs` - Replace skeleton
- `config.toml` - Already has basic patterns
- `Cargo.toml` - Add new dependencies

## Reference Files (Python to port)

- `claude-code-safety-net/scripts/safety_net_impl/hook.py` (1286 lines) - Main logic
- `claude-code-safety-net/scripts/safety_net_impl/shell.py` (216 lines) - Shell parsing
- `claude-code-safety-net/scripts/safety_net_impl/rules_git.py` (333 lines) - Git rules
- `claude-code-safety-net/scripts/safety_net_impl/rules_rm.py` (158 lines) - rm rules
