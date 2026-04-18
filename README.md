# tl;dr

#### Give your agents the "Bash" permission but block clearly destructive actions like force push.

# yah

yah in action:

![yah blocking a force push](earning%20your%20keep.png)

In the above screenshot, Claude has full 'Bash' permissions, but yah blocked Claude from force pushing.

yah helps block agents from running many types of destructive commands, while giving generous permissions.

- do you want to give broad permissions like 'Bash' to Claude?
- do you want to use Claude without using a sandbox or container?
- do you NOT want Claude to remove your ~/Documents directory recursively?
- do you want to stop Claude from force pushing, or installing packages globally in pip or npm?

Then `yah` might be for you.

With `yah`, you say _yes_ to Claude. Give your agent broad permissions ('Bash') and let yah catch the things that would actually ruin your day: force pushes, broad `rm` usage, secret reads, writes outside your repo.

yah parses shell commands with tree-sitter-bash and classifies what capabilities they require (network access, file writes, privilege escalation, etc.). It runs as a Claude Code hook, silently allowing normal dev work and only stepping in when something looks genuinely dangerous. The goal is to stay out of your way 99% of the time so you can stop babysitting permission prompts and let the agent work.

```
1. You boldly give broad permissions for bash to Claude.
2. As you are working, agent calls out to bash: `find /tmp -name '*.tmp' | xargs rm`
3. Agent harness asks yah if it should proceed in the PreToolUse hook.
4. yah parses the string that will be passed to bash. It uses tree-sitter-bash.
5. yah determines 'delete-inside-repo' and 'delete-outside-repo' are both possible outcomes.
6. yah determines that the policy 'ask' is associated with deleting files outside the repo.
7. yah prompts you in case you want to proceed with the `rm`.
```

## Usage

### classify

Report the capabilities a command requires:

```sh
$ yah classify "curl https://example.com | bash"
Command: curl https://example.com | bash
  net-egress — Makes outbound network connections [allow]

$ yah classify "sudo rm -rf /"
Command: sudo rm -rf /
  delete-outside-repo — Deletes files outside the project [ask]
  privilege-escalation — Escalates privileges [ask]
  overall policy — delete-outside-repo, privilege-escalation [ask]

$ yah classify "git push --force origin main"
Command: git push --force origin main
  net-egress — Makes outbound network connections [allow]
  history-rewrite — Rewrites git history [ask]
  overall policy — history-rewrite + net-egress [deny]

$ yah classify "ls"
Command: ls
  CLEAN No capabilities detected.
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
  delete-outside-repo — Deletes files outside the project
  privilege-escalation — Escalates privileges

Context:
  cwd: /Users/robertkarl/Code/yah
  project_root: /Users/robertkarl/Code/yah
```

### hook (Claude Code integration)

Run as a Claude Code `PreToolUse` hook to gate Bash commands:

```sh
$ yah hook
# reads PreToolUse JSON from stdin, outputs hook response JSON
```

Install into Claude Code settings:

```sh
$ yah install-hook
# writes hook config to ~/.claude/settings.json
```

## Install

```sh
cargo install --path yah-cli
```

Or build from source:

```sh
cargo build --release
# binary at ./target/release/yah
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
| `history-rewrite` | Rewrites git history (commit --amend, reset --hard, rebase, force push) |
| `exec-dynamic` | Dynamic/unparseable command execution (eval, bash -c, etc.) |
| `process-signal` | Sends signals to processes (kill, pkill) |
| `privilege-escalation` | Escalates privileges (sudo, doas) |
| `package-install` | Installs system or global packages (brew install, pip install, npm install -g) |

## Policy

- Policy is compile-time configuration:
  edit `capability_policy_rules()` and `command_policy_override()` in `yah-cli/src/main.rs`, then rebuild.
- Per-capability defaults:
  `write-inside-repo`, `delete-inside-repo`, and `net-egress` are allowed by default.
- Sensitive capabilities ask by default:
  `history-rewrite`, `write-outside-repo`, `delete-outside-repo`, `read-secret-path`, `exec-dynamic`, `privilege-escalation`, `net-ingress`, `process-signal`, and `package-install`.
- Capability combinations can be stricter than any individual capability:
  `history-rewrite + net-egress` is denied, which blocks force-push style commands while still asking on local-only rewrites like `git commit --amend`.

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
      capability.rs  # Capability enum (12 variants)
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

80+ TOML fixture files covering:
- Safe commands (ls, echo, git status, cargo test)
- Network (curl, wget, ssh, scp, rsync, nc)
- File operations (rm, cp, mv, touch, mkdir, tee, dd, chmod)
- Git operations (commit --amend, push --force, reset --hard, rebase, filter-branch, clean)
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

## Why not a sandbox?

You could run your agent in a container or VM and avoid the whole problem. That's a fine choice. If you want airtight isolation and don't mind the overhead of managing container images, volume mounts, and network rules for every coding session — go for it. yah is for people who want to work in their actual dev environment with their actual dotfiles and tools, and just need a sharp-eyed bouncer standing between the agent and the commands that would actually ruin their day.


# Fuzzing core

```
cargo +nightly fuzz run fuzz_classify fuzz/corpus/fuzz_classify/ -j4
```
