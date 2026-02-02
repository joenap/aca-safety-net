# Discovery: Anthropic's sandbox-runtime

## The Find

Anthropic already has an experimental sandboxing tool: [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime)

It does almost exactly what we proposed for the sandbox layer.

---

## What sandbox-runtime Does

A lightweight sandboxing tool that enforces filesystem and network restrictions on arbitrary processes at the OS level, without requiring a container.

**Core capabilities:**
- Filesystem restrictions (read/write control)
- Network restrictions (domain allowlists via proxies)
- Unix socket restrictions
- Violation monitoring (macOS)

**Platform support:**
- Linux: bubblewrap + socat + network namespace isolation
- macOS: sandbox-exec with dynamic Seatbelt profiles

**Form factor:**
- CLI tool: `srt "curl example.com"`
- Library: TypeScript/JS npm package

---

## Feature Comparison

| Feature | sandbox-runtime | ACA Safety Net (proposed) |
|---------|-----------------|---------------------------|
| Sandbox engine | bubblewrap, sandbox-exec | Same |
| Filesystem isolation | ✓ | ✓ |
| Network isolation | ✓ (domain allowlists, proxies) | ✓ |
| Unix socket control | ✓ | ✓ |
| Violation monitoring | ✓ (macOS) | Not planned |
| Implementation | TypeScript/JS | Rust |
| Focus | General process sandboxing | AI coding agents |

---

## What sandbox-runtime Has That We Need

- The hard part: bubblewrap/sandbox-exec integration
- Network filtering via HTTP/SOCKS5 proxies
- Filesystem read/write restrictions
- Cross-platform (Linux + macOS)
- Already built and tested

---

## What We Have That sandbox-runtime Doesn't

| Feature | Why We Need It |
|---------|----------------|
| **Hook layer** | Guidance messages when agent is blocked ("use fd instead of find") |
| **Safe tool wrappers** | Replace dangerous commands (find, xargs) with safe alternatives |
| **Git/credential proxy** | Run privileged commands outside sandbox, return results |
| **AI-agent UX** | "Don't read secrets, don't wreck stuff, give visibility" |
| **Stats/visibility** | Dashboard showing what's blocked, audit logs |
| **Rust implementation** | Consistent with existing codebase |

---

## The Decision

**Three options:**

### Option A: Use sandbox-runtime as dependency

```
aca-safety-net run claude
       │
       ▼
  ACA Layer (Rust)
  - Safe tools, git proxy, hook, UX
       │
       ▼
  sandbox-runtime (TypeScript)
  - Filesystem/network sandboxing
       │
       ▼
  bubblewrap / sandbox-exec
```

**Pros:**
- Don't reinvent sandboxing
- Benefit from Anthropic's testing
- Faster to ship

**Cons:**
- TypeScript dependency in Rust project
- "Experimental" status
- Less control over sandbox behavior
- Two languages in stack

### Option B: Build sandbox layer in Rust

```
aca-safety-net run claude
       │
       ▼
  ACA Layer (Rust)
  - Safe tools, git proxy, hook, UX
  - Sandbox orchestration
       │
       ▼
  bubblewrap / sandbox-exec (direct)
```

**Pros:**
- Full control
- Single language (Rust)
- Can optimize for our use case
- No external dependency risk

**Cons:**
- More work
- Reimplementing what exists
- Need to handle edge cases sandbox-runtime already solved

### Option C: Port sandbox-runtime concepts to Rust

Take the architecture and learnings from sandbox-runtime, reimplement in Rust.

**Pros:**
- Best of both worlds
- Learn from their design decisions
- Rust-native

**Cons:**
- Still significant work
- May miss nuances from original

---

## Recommendation

**Lean toward Option B or C.**

Rationale:
1. sandbox-runtime is "experimental" - unclear maintenance commitment
2. TypeScript/Rust interop adds complexity
3. The bubblewrap/sandbox-exec layer isn't that complex - it's mostly CLI flags
4. We need tight integration with our git proxy, safe tools, etc.
5. Our Rust codebase is already ~4,100 lines - we can handle this

**What to take from sandbox-runtime:**
- Architecture: proxy-based network filtering via Unix sockets
- The specific bubblewrap flags and sandbox-exec profiles
- Lessons learned (check their issues/commits)

**What to build ourselves:**
- Rust implementation of sandbox orchestration
- Git proxy daemon
- Safe tool wrappers
- Hook integration
- AI-agent-specific UX

---

## Architecture (If We Build Our Own)

```
┌─────────────────────────────────────────────────────────────┐
│  aca-safety-net run claude                                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  src/launcher/                                              │
│  ├── mod.rs          # CLI handling                        │
│  ├── sandbox/                                               │
│  │   ├── mod.rs      # Platform detection                  │
│  │   ├── linux.rs    # bubblewrap invocation               │
│  │   └── macos.rs    # sandbox-exec profile generation     │
│  ├── proxy/                                                 │
│  │   ├── mod.rs      # Proxy daemon orchestration          │
│  │   ├── git.rs      # Git command proxy                   │
│  │   └── network.rs  # HTTP/SOCKS proxy (future)           │
│  └── tools/                                                 │
│      ├── mod.rs      # Safe tool management                │
│      └── wrappers.rs # Generate wrapper scripts            │
│                                                             │
│  Existing:                                                  │
│  src/rules/          # Hook layer (guidance messages)      │
│  src/shell/          # Command parsing                     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Next Steps

1. Study sandbox-runtime source more deeply
2. Document the exact bubblewrap flags they use
3. Document the sandbox-exec profile format
4. Decide: Option B (build from scratch) or Option C (port concepts)
5. Prototype the git proxy first (hardest novel piece)
