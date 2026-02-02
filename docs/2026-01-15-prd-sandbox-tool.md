# PRD: ACA Safety Net Sandbox Launcher

## Overview

A launcher that runs AI coding agents inside an ephemeral, per-invocation sandbox. Hard security via OS-level isolation, helpful UX via the existing hook.

**The command:**
```
$ cd ~/projects/myapp
$ aca-safety-net run claude
```

That's it. No setup. No separate user. No ACLs. Just works.

---

## The Problem

Developers want to run AI agents on their laptop with full autonomy. But:

1. **Secrets are everywhere** - `~/.ssh`, `~/.aws`, `.env` files
2. **Accidents happen** - `rm -rf /`, `git push -f main`
3. **Current solution (hook only) has gaps** - can be bypassed via indirect access

The hook catches obvious attempts but can't stop:
- `python -c "open('.env').read()"`
- `$VAR` expansion tricks
- Symlink traversal

**We need OS-level enforcement.**

---

## The Solution

Wrap agent execution in a platform-native sandbox that:

1. **Exposes** the current project directory (read/write)
2. **Exposes** system binaries and libraries (read-only)
3. **Hides** secrets by mounting empty tmpfs over sensitive paths
4. **Provides** safe tool alternatives in PATH
5. **Runs** the hook inside for guidance/UX

```
┌─────────────────────────────────────────────────────────────┐
│  aca-safety-net run <agent>                                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  SANDBOX                                                    │
│  ════════                                                   │
│  Visible (rw):   /current/project                          │
│  Visible (ro):   /usr, /bin, /lib, safe tools              │
│  Hidden:         ~/.ssh, ~/.aws, ~/.env, ~/.gnupg          │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Agent (claude, opencode, etc.)                     │   │
│  │  + ACA Safety Net hook (guidance layer)             │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Two-Layer Security Model

| Layer | Mechanism | Role |
|-------|-----------|------|
| **Sandbox** | OS namespaces / kernel sandbox | Hard enforcement - secrets don't exist |
| **Hook** | Pre-execution analysis | Guidance - helpful error messages |

**Example flow:**
```
Agent: cat ~/.ssh/id_rsa
Sandbox: (file doesn't exist - it's a tmpfs)
OS: "No such file or directory"
Hook: "SSH keys are not available in this sandbox.
       Ask the user if you need SSH configured for git operations."
```

The sandbox makes bypass impossible. The hook makes the experience good.

---

## Platform Implementation

### Linux: bubblewrap

[Bubblewrap](https://github.com/containers/bubblewrap) is a lightweight, unprivileged sandboxing tool using Linux namespaces.

```bash
bwrap \
  --bind $PWD $PWD \
  --ro-bind /usr /usr \
  --ro-bind /bin /bin \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --symlink /usr/lib /lib \
  --dev /dev \
  --proc /proc \
  --tmpfs /tmp \
  --tmpfs $HOME/.ssh \
  --tmpfs $HOME/.aws \
  --tmpfs $HOME/.gnupg \
  --tmpfs $HOME/.config/gcloud \
  --setenv PATH "/opt/aca-safe-tools/bin:$PATH" \
  --die-with-parent \
  -- claude
```

**Key features:**
- Unprivileged (no root needed after install)
- Namespace isolation (mount, PID, network optional)
- Bind mounts with permission control
- tmpfs overlays to hide sensitive directories

### macOS: sandbox-exec

[sandbox-exec](https://jmmv.dev/2019/11/macos-sandbox-exec.html) uses Apple's Seatbelt sandbox framework.

```scheme
(version 1)
(deny default)

; Allow read-only system access
(allow file-read*
    (subpath "/usr")
    (subpath "/bin")
    (subpath "/Library")
    (subpath "/System"))

; Allow read-write to project directory
(allow file-read* file-write*
    (subpath (param "PROJECT_DIR")))

; Block secrets explicitly (belt and suspenders)
(deny file-read*
    (subpath (string-append (param "HOME") "/.ssh"))
    (subpath (string-append (param "HOME") "/.aws"))
    (subpath (string-append (param "HOME") "/.gnupg"))
    (regex #"\.env"))

; Allow process execution
(allow process-exec)
(allow process-fork)

; Allow basic system operations
(allow sysctl-read)
(allow mach-lookup)
```

**Key features:**
- Kernel-level enforcement (MACF)
- Deny-by-default with explicit allows
- Path-based and regex-based rules
- Note: Deprecated but still functional and widely used by macOS itself

---

## Safe Tools

On install, we provide safe alternatives to dangerous commands:

| Dangerous | Problem | Safe Alternative |
|-----------|---------|------------------|
| `find` | `-exec`, `-delete` | `fd` (no exec capability) |
| `xargs` | Arbitrary command piping | Direct commands |
| `parallel` | Same as xargs | Sequential execution |
| `rm` | Can delete anything | `safe-rm` (workspace only) |

**Installation (via brew/apt):**
```bash
# Installed to /opt/aca-safe-tools/bin or similar
fd          # find alternative
rg          # grep alternative
safe-rm     # rm that only works in workspace
```

**Wrapper scripts for dangerous commands:**
```bash
# /opt/aca-safe-tools/bin/find
#!/bin/bash
echo "find is disabled in this sandbox."
echo "Use 'fd' instead: fd -e js  (find JS files)"
echo "Or use the agent's built-in Glob tool."
exit 1
```

The sandbox sets PATH to prioritize safe tools:
```bash
PATH=/opt/aca-safe-tools/bin:$PATH
```

---

## Installation Flow

```
$ brew install aca-safety-net
# or: cargo install aca-safety-net

$ aca-safety-net install

ACA Safety Net Setup
━━━━━━━━━━━━━━━━━━━━

Installing sandbox components...

Linux detected. Installing bubblewrap...
  brew install bubblewrap ✓

Installing safe tools...
  fd ✓
  rg ✓
  safe-rm ✓

Creating wrapper scripts...
  /opt/aca-safe-tools/bin/find ✓
  /opt/aca-safe-tools/bin/xargs ✓

Installing hook configuration...
  ~/.claude/settings.json ✓

Setup complete!

Run AI agents safely with:
  aca-safety-net run claude
  aca-safety-net run opencode
```

---

## Usage

### Basic Usage

```bash
# Run Claude on current project
$ cd ~/projects/myapp
$ aca-safety-net run claude

# Run OpenCode
$ aca-safety-net run opencode

# Run any command in sandbox
$ aca-safety-net run bash
```

### Options

```bash
# Allow network access (default: allowed)
$ aca-safety-net run --network claude

# Block network access
$ aca-safety-net run --no-network claude

# Add additional directory access
$ aca-safety-net run --allow ~/shared-libs claude

# Verbose mode (show sandbox config)
$ aca-safety-net run -v claude
```

### What the Agent Sees

```
$ aca-safety-net run bash

bash$ pwd
/home/user/projects/myapp

bash$ ls ~/.ssh
ls: cannot access '/home/user/.ssh': No such file or directory

bash$ cat .env
cat: .env: No such file or directory

bash$ find . -exec rm {} \;
find is disabled in this sandbox.
Use 'fd' instead: fd -e js  (find JS files)

bash$ fd -e js
src/index.js
src/utils.js
tests/test.js
```

---

## Hidden Paths (Secrets)

Default paths hidden via tmpfs overlay:

| Path | Contains |
|------|----------|
| `~/.ssh` | SSH keys |
| `~/.aws` | AWS credentials |
| `~/.gnupg` | GPG keys |
| `~/.config/gcloud` | GCloud credentials |
| `~/.azure` | Azure credentials |
| `~/.kube` | Kubernetes configs |
| `~/.docker/config.json` | Docker registry auth |
| `~/.netrc` | Network credentials |
| `~/.npmrc` | NPM tokens |
| `~/.pypirc` | PyPI tokens |

Configurable via:
```toml
# ~/.config/aca-safety-net/config.toml
[sandbox]
hide_paths = [
    "~/.ssh",
    "~/.aws",
    "~/.my-custom-secrets",
]
```

---

## Project Directory Access

**Default:** Current working directory when `run` is invoked.

```bash
$ cd ~/projects/myapp
$ aca-safety-net run claude
# Agent can access ~/projects/myapp/**
```

**Additional directories:**
```bash
$ aca-safety-net run --allow ~/shared-components claude
# Agent can access both ~/projects/myapp and ~/shared-components
```

**Persistent configuration:**
```toml
# ~/projects/myapp/.aca-safety-net.toml
[sandbox]
allow_paths = [
    "../shared-libs",
    "~/company/design-system",
]
```

---

## Network Control (Future)

Phase 1: Full network access (current)
Phase 2: Optional network isolation

```bash
# No network
$ aca-safety-net run --no-network claude

# Allowlist specific domains
$ aca-safety-net run --allow-domain github.com --allow-domain npmjs.org claude
```

Implementation:
- Linux: `--unshare-net` in bubblewrap + network namespace with iptables
- macOS: `(deny network*)` with `(allow network* (remote host "github.com"))` in sandbox profile

---

## Architecture

```
src/
├── main.rs
├── cli/
│   ├── mod.rs
│   ├── run.rs          # aca-safety-net run
│   └── install.rs      # aca-safety-net install
├── sandbox/
│   ├── mod.rs
│   ├── linux.rs        # bubblewrap implementation
│   ├── macos.rs        # sandbox-exec implementation
│   └── config.rs       # sandbox configuration
├── safe_tools/
│   ├── mod.rs
│   ├── wrappers.rs     # generate wrapper scripts
│   └── install.rs      # install fd, rg, etc.
├── hook/               # existing hook code
│   └── ...
└── platform/
    ├── mod.rs
    ├── linux.rs
    └── macos.rs
```

---

## Migration Path

**Current users:**
- Hook-only mode continues to work
- `aca-safety-net run` is additive, not required

**Recommended path:**
1. Keep using hook for guidance/UX
2. Adopt `run` command for hard security
3. Eventually: `run` becomes the default way

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Install time | < 2 minutes |
| Startup overhead | < 100ms |
| Secret access | 0 (impossible, not just blocked) |
| Project file access | 100% (no false positives) |
| Platform support | Linux + macOS |

---

## Open Questions

1. **Windows support?** - WSL2 could use Linux path, native Windows is harder
2. **IDE integration?** - VS Code terminal, Cursor, etc. - how to make `run` the default?
3. **Git credentials?** - Agent needs to push/pull. Credential helper injection?
4. **Homebrew PATH issues?** - User's brew-installed tools need to be visible
5. **Shell config** - `.bashrc`/`.zshrc` might leak secrets via env vars

---

## Non-Goals

- **Full container isolation** - Use Docker if you want that
- **Windows native support** - WSL2 is the path for Windows
- **Network filtering** - Phase 2, not v1
- **Multi-user scenarios** - This is for your laptop, not a server

---

## Summary

**What we're building:**
A launcher that wraps AI agents in a platform-native sandbox, making secret access impossible (not just blocked) while maintaining full project access.

**The UX:**
```
$ aca-safety-net run claude
```

**The security model:**
- Sandbox = hard enforcement (OS-level)
- Hook = guidance layer (helpful messages)

**Platform support:**
- Linux: bubblewrap (namespaces)
- macOS: sandbox-exec (Seatbelt)
