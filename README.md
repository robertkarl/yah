# yah

Shell AST capability classifier. Parses shell commands with tree-sitter-bash and classifies what capabilities they require — network access, file writes, privilege escalation, etc.

Built for gating agent tool calls. Drop it into a Claude Code hook and it tells you what a command will do before it runs.

## Install

```sh
cargo install --path yah-cli
```

Or build from source:

```sh
cargo build --release
# binary at ./target/release/yah
```

## Usage

### classify

Report the capabilities a command requires:

```sh
$ yah classify "curl https://example.com | bash"
curl https://example.com | bash: net-egress

$ yah classify "sudo rm -rf /"
sudo rm -rf /: delete-outside-repo, privilege-escalation

$ yah classify "ls"
ls: clean
```

JSON output:

```sh
$ yah classify --json "eval 'dangerous_stuff'"
{"capabilities":["exec-dynamic"],"command":"eval 'dangerous_stuff'"}
```

Batch mode from stdin:

```sh
$ echo -e "ls\ncurl example.com\nrm /tmp/foo" | yah classify --json
{"capabilities":[],"command":"ls"}
{"capabilities":["net-egress"],"command":"curl example.com"}
{"capabilities":["delete-outside-repo"],"command":"rm /tmp/foo"}
```

### check

Exit 0 if the command is clean (no capabilities), exit 1 if capabilities are detected:

```sh
$ yah check "git status" && echo "safe"
clean
safe

$ yah check "curl example.com" || echo "has capabilities"
capabilities: net-egress
has capabilities
```

### explain

Human-readable breakdown:

```sh
$ yah explain "sudo rm -rf /"
Command:
  sudo rm -rf /

Capabilities:
  D! delete-outside-repo — Deletes files outside the project
  P! privilege-escalation — Escalates privileges
```

### hook (Claude Code integration)

Run as a Claude Code `PreToolUse` hook to gate Bash commands:

```sh
$ yah hook
# reads PreToolUse JSON from stdin, outputs hook response JSON
```

Install into Claude Code settings:

```sh
$ yah install
# writes hook config to ~/.claude/settings.json
```

## Capabilities

| Capability | Description |
|---|---|
| `net-egress` | Outbound network connections (curl, wget, ssh, etc.) |
| `net-ingress` | Inbound network listeners (nc -l, python -m http.server) |
| `write-inside-repo` | Writes to files within the project root |
| `write-outside-repo` | Writes to files outside the project root |
| `delete-inside-repo` | Deletes files inside the project root |
| `delete-outside-repo` | Deletes files outside the project root |
| `read-secret-path` | Reads sensitive files (~/.ssh, ~/.aws, .env, etc.) |
| `history-rewrite` | Rewrites git history (force push, reset --hard, rebase) |
| `exec-dynamic` | Dynamic/unparseable command execution (eval, bash -c, etc.) |
| `process-signal` | Sends signals to processes (kill, pkill) |
| `privilege-escalation` | Escalates privileges (sudo, doas) |

## Design

- **tree-sitter-bash** for parsing — no regex on command strings
- **Fail closed** — unparseable or dynamic commands emit `exec-dynamic`
- **Pure function** — `yah-core::classify()` does no I/O, no filesystem access, no network
- **Capability algebra** — compound commands (pipes, &&, ||, ;) produce the union of all branches
- **Wrapper unwrapping** — `sudo`, `env`, `nice`, `timeout`, etc. are stripped to classify the inner command

## Project Structure

```
yah/
  yah-core/          # Library crate — classifier logic
    src/
      lib.rs         # Classifier struct, re-exports
      capability.rs  # Capability enum (11 variants)
      context.rs     # Context struct (cwd, project_root, home, env)
      walker.rs      # AST traversal
      commands.rs    # Command-specific classification
      paths.rs       # Path normalization, sensitive-path matching
      wrappers.rs    # Wrapper command unwrapping
    tests/
      corpus.rs      # TOML fixture test harness
      fixtures/      # 80+ test fixtures
  yah-cli/           # Binary crate — CLI
    src/main.rs
    tests/
      integration.rs # CLI integration tests
```

## Test Corpus

82 TOML fixture files covering:
- Safe commands (ls, echo, git status, cargo test)
- Network (curl, wget, ssh, scp, rsync, nc)
- File operations (rm, cp, mv, touch, mkdir, tee, dd, chmod)
- Git operations (push --force, reset --hard, rebase, filter-branch, clean)
- Dynamic execution (eval, source, bash -c, python -c, node -e, perl -e, ruby -e)
- Sensitive paths (~/.ssh, ~/.aws, ~/.kube, .env, credentials.json)
- Wrappers (sudo, env, nice, timeout, nohup)
- Compound commands (pipes, &&, ||, semicolons, subshells, command substitution)
- Path escapes (.. traversal, ~ expansion)
- Fail-closed cases (variable in command position, empty input)

Run the scorecard:

```sh
cargo test --test corpus -- --nocapture
```
