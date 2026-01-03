# Claude Code Instructions for aca-safety-net

## CRITICAL: Testing the Security Hook

Even if the hook *should* block something, you must NEVER attempt to run commands that could leak real secrets - because if the hook has a bug, is misconfigured, or has an edge case, actual secrets would be exposed.

### Rules

1. **Use `just test` or `cargo test`** - the test suite has 177 tests covering all blocking scenarios
2. **Do NOT manually test the hook** by piping JSON or running commands - the test suite already covers this
3. NEVER run `env`, `printenv`, `history`, or read real SSH keys, real `.env` files, real AWS credentials, etc.
4. If manual testing is absolutely required, use ONLY the `./test_input/` directory

### Test Input Directory

The `./test_input/` directory contains fake sensitive files for testing:

- `test_input/.env` - fake environment variables
- `test_input/.env.local` - fake local env
- `test_input/.ssh/id_rsa` - fake SSH key
- `test_input/.aws/credentials` - fake AWS creds
- `test_input/.netrc` - fake netrc
- `test_input/server.pem` - fake certificate

These files contain obviously fake data. If the hook fails and you see this data, nothing real was leaked.

### Example: Testing the Hook

```bash
# CORRECT - uses fake test data
cat test_input/.env

# WRONG - could leak real secrets if hook fails
cat ~/.ssh/id_rsa
printenv
cat /home/user/.env
```

## Development

- Run tests: `just test`
- Build release: `just release`
- **Install: `just install`** (NEVER manually cp the binary - always use this command)
- Full CI check: `just ci`
