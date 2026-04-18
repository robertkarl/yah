# TODOS

## Post-v0

### Measure ExecDynamic false-positive rate on real agent transcripts
**Priority:** High
**Why:** The outside voice (eng review 2026-04-17) flagged that if 40%+ of real agent commands collapse to ExecDynamic, the classifier is useless in practice. This is the key metric for whether yah is actually useful vs. theoretically sound.
**How:** Collect a corpus of real Claude Code bash commands (from hook logs or session transcripts). Run `yah classify` on each. Report % that contain ExecDynamic. Identify which ExecDynamic triggers are noisy vs. legitimate.
**Depends on:** v0 implementation complete.

### Add --hook output mode for Claude Code PreToolUse JSON response
**Priority:** High
**Why:** `yah check` gives exit codes (0/1) which works but requires a wrapper script to produce PreToolUse JSON. A native `yah hook` subcommand removes friction and makes yah directly usable as a Claude Code hook with one line of config.
**Depends on:** v0 CLI complete. Needs Claude Code hook format spec.

### Benchmark cold-start latency
**Priority:** Medium
**Why:** The sub-millisecond target should be verified against cold-start (full process spawn + grammar load), not warm-path. If yah is called per-command in a hook, cold-start is what the user feels. Use `hyperfine` or similar to measure wall-clock from spawn to output for `yah classify "ls"`.
**Depends on:** v0 CLI complete.
