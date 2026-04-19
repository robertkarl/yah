# Design: Narrow Constant Propagation for Shell-Local Variables

## Goal

Improve yah's classifier so simple shell-local assignments can sharpen capability detection inside a single shell snippet.

Primary motivating example:

```sh
FLAGS=--force && git push $FLAGS
```

Today yah classifies this as:

- `net-egress`
- `exec-dynamic`

That is fail-closed enough to produce an `ask`, but it does not recover the stronger fact that this is effectively `git push --force`, which should classify as:

- `net-egress`
- `history-rewrite`

and therefore hit the `history-rewrite + net-egress -> deny` policy rule.

The feature proposed here is deliberately narrow. It is not "shell evaluation." It is a small amount of constant propagation over shell-local scalar assignments so yah can recover obvious literal flags without becoming unsound.

## Non-Goals

- Full shell execution semantics
- Full environment modeling
- Word splitting, globbing, brace expansion, arithmetic expansion, or arrays
- Evaluating `eval`, `source`, command substitution, process substitution, or runtime-generated values
- Cross-file or cross-process state
- Replacing `exec-dynamic` with optimism when the classifier is unsure

If the implementation has to choose between precision and soundness, it should keep `exec-dynamic`.

## Current State

Today yah resolves variable expansions only from `Context.env`, which represents ambient process environment, not shell-local bindings created inside the snippet itself. The walker sees a `variable_assignment` node, but only recurses into nested command substitutions for capability extraction; it does not record the binding for later use.

That means:

```sh
VALS=--force && git push $VALS
```

cannot currently resolve `$VALS` to `--force`. yah instead recognizes that a dynamic git arg is present and emits `exec-dynamic` as a bandaid.

## Design Principles

- Keep `yah-core` pure and deterministic.
- Track only values that are statically known string literals after existing expansion rules.
- Prefer explicit scope invalidation over optimistic propagation.
- Limit propagation to places where shell execution order is simple enough to reason about cheaply.
- Keep the implementation small enough that a reviewer can audit the entire propagation path.

## Proposed Semantics

### Supported Binding Forms

Track only shell-local scalar assignments with statically-known values:

```sh
FLAGS=--force
TARGET="./tmp/out.txt"
NAME="$HOME/.ssh/id_rsa"    # only if current resolver can fully resolve it
export FLAGS=--force        # optional v1 if implemented with the same rules
declare FLAGS=--force       # optional v1 if implemented with the same rules
```

A binding is eligible for propagation only when its right-hand side resolves to a single static string using the same fail-closed rules yah already uses for words and quoted strings.

### Unsupported Binding Forms

These should not propagate and should preserve `exec-dynamic` behavior when referenced later:

```sh
FLAGS=$(compute_flags)
FLAGS=`compute_flags`
FLAGS="${X:---force}"
FLAGS=$((1 + 2))
FLAGS=*.txt
FLAGS=(--force)
read FLAGS
source env.sh
eval "FLAGS=--force"
```

The classifier may record these bindings as "unknown" so later `$FLAGS` references fail closed.

### Binding Lookup Order

When resolving `$VAR` or `${VAR}`:

1. Check shell-local propagated bindings.
2. Fall back to `Context.env`.
3. If neither resolves statically, treat the expansion as unresolved.

This lets shell-local values shadow ambient environment variables, which matches user expectations and shell behavior more closely than the current model.

## Scope Model

Introduce a small local binding environment separate from `Context.env`.

```rust
enum BoundValue {
    Literal(String),
    Unknown,
}

struct LocalScope {
    bindings: BTreeMap<String, BoundValue>,
}
```

The scope is flow-sensitive, not global.

### Scope Boundaries

Bindings should propagate only within the current shell scope. The following nodes create a child scope whose writes do not flow back to the parent:

- `subshell`
- `command_substitution`
- `process_substitution`
- pipeline segments
- function bodies

This keeps propagation aligned with shell-local semantics:

```sh
(FLAGS=--force); git push $FLAGS
```

must remain dynamic in the outer command.

Pipelines deserve explicit conservatism. Shells differ on when pipeline elements share process state, and even where behavior is stable it is easy to misunderstand. For v1, bindings should not propagate:

- from one pipeline segment to another
- out of a pipeline back into the enclosing scope

## Control-Flow Model

The key difficulty is not storing bindings; it is deciding when later nodes definitely observe them.

The cleanest abstraction is to have the walker return both capabilities and a conservative flow result:

```rust
struct AnalysisResult {
    caps: HashSet<Capability>,
    out_scope: LocalScope,
    flow: FlowInfo,
}

enum FlowInfo {
    Continues,        // later siblings definitely see out_scope
    MayNotContinue,   // later siblings might not run, or scope effects are not trustworthy
}
```

For this feature, we only need a narrow subset of flow reasoning:

- Standalone static assignment command: `Continues`
- `;` / newline sequencing: propagate left-to-right
- `&&`: propagate left-to-right only when the left side is a static assignment-only command that definitely succeeds
- `||`: do not propagate from left to right
- Branching / looping constructs: analyze child scopes for capabilities, but invalidate propagated bindings afterward

This is enough to correctly handle the motivating examples without pretending to understand arbitrary shell control flow.

## AST Handling

### 1. Add Assignment Extraction

Add a helper that recognizes static assignment nodes and returns:

```rust
fn extract_static_assignment(...) -> Option<(String, BoundValue)>
```

Rules:

- left-hand side must be a simple variable name
- right-hand side must resolve via existing literal/quoted-string expansion logic
- if the right-hand side contains unsupported expansion features, record `Unknown`

### 2. Thread Local Scope Through Resolution

Update the variable resolution helpers so they consult `LocalScope` before `Context.env`.

Likely touch points:

- `resolve_expansion`
- `expand_simple_vars`
- `resolve_word`
- `resolve_string`

This should be done via an explicit resolver input rather than mutating `Context`.

### 3. Replace Pure Union Walking for Sequential Nodes

Today `program`, `list`, and `compound_statement` simply union children.

For this feature, these nodes need ordered analysis:

- analyze child
- merge its capabilities
- update local scope if flow allows
- continue to next child with the new scope

This is the main architectural change.

### 4. Preserve Fail-Closed Behavior on Unsupported Constructs

If a later sensitive command depends on an unknown propagated value, keep or add `exec-dynamic`.

Examples:

```sh
FLAGS=$(cat f) && git push $FLAGS
git reset ${MODE:---hard}
```

These should not silently downgrade to clean or to non-history-sensitive variants.

## Supported Examples

These should become more precise after the feature:

```sh
FLAGS=--force && git push $FLAGS
FLAGS='--force-with-lease'; git push $FLAGS origin main
MODE=--hard; git reset $MODE HEAD~1
TARGET=~/.ssh/id_rsa; cat $TARGET
OUT=/etc/yah.conf; echo hi > $OUT
```

Expected benefit:

- fewer "ask because dynamic" results for obviously literal values
- more true `history-rewrite`, `read-secret-path`, and write/delete classifications

## Unsupported or Intentionally Conservative Examples

These should remain dynamic or otherwise fail closed:

```sh
if cond; then FLAGS=--force; fi; git push $FLAGS
FLAGS=--force || git push $FLAGS
FLAGS=$(printf -- --force); git push $FLAGS
local FLAGS=--force; git push $FLAGS
FLAGS=--force git push $FLAGS
unset FLAGS; git push $FLAGS
```

The last example is intentionally conservative for v1. Prefix assignments attached to a command are semantically trickier than standalone assignments, and the feature does not need them to solve the motivating case.

## Safety Limits

To avoid accidental complexity growth, the implementation should impose hard limits:

- max propagated bindings per scope: e.g. 64
- max binding value length: e.g. 512 bytes
- no recursive propagation through self-referential assignments
- no propagation through arrays or multi-word semantic values

When a limit is exceeded, mark the binding `Unknown` and continue fail-closed.

## Testing Plan

Add corpus fixtures and unit tests for at least these cases:

### Should Resolve

- `FLAGS=--force && git push $FLAGS` -> `history-rewrite`, `net-egress`
- `MODE=--hard; git reset $MODE HEAD~1` -> `history-rewrite`
- `TARGET=~/.ssh/id_rsa; cat $TARGET` -> `read-secret-path`
- `OUT=/etc/yah.conf; echo hi > $OUT` -> `write-outside-repo`

### Should Stay Dynamic

- `FLAGS=$(cat flags.txt) && git push $FLAGS` -> `net-egress`, `exec-dynamic`
- `FLAGS=--force || git push $FLAGS` -> `net-egress`, `exec-dynamic`
- `(FLAGS=--force); git push $FLAGS` -> `net-egress`, `exec-dynamic`
- `if true; then FLAGS=--force; fi; git push $FLAGS` -> `net-egress`, `exec-dynamic`

### Shadowing / Overwrite

- `FLAGS=--force; FLAGS=--force-with-lease; git push $FLAGS`
- `FLAGS=--force; FLAGS=$(cat flags); git push $FLAGS` -> dynamic
- `FLAGS=--force; unset FLAGS; git push $FLAGS` -> dynamic

## Rollout Strategy

1. Land the scope and resolver plumbing without enabling new cases.
2. Enable propagation only for standalone assignment statements followed by `;` / newline.
3. Add narrow `&&` support for assignment-only left-hand sides that definitely succeed.
4. Expand to `export` / `declare` only if tests show the semantics remain unsurprising.

Each step should preserve existing fail-closed behavior for unsupported forms.

## Alternatives Considered

### Keep the Current Bandaid

Status quo is to emit `exec-dynamic` for suspicious git args. This is simple and safe, but it permanently leaves precision on the table for obvious literal flag passing.

### Full Shell Evaluation

Rejected. Too much complexity, too much risk of unsoundness, and too far from yah's design center as a fast, auditable static classifier.

### String-Rewrite Heuristics for Known Patterns

Rejected. Hard-coding `VAR=--force && git push $VAR`-style regexes would be brittle and would undermine the AST-first architecture.

## Open Questions

- Should `export VAR=literal` be in scope for v1, or should v1 only support bare assignment statements?
- Is there any command-prefix assignment form we can support safely without modeling more shell semantics?
- Do we want a dedicated `AnalysisResult` refactor now, or should the first version special-case just enough flow for `program`, `list`, and `compound_statement`?

## Implementation Notes

- `unset VAR`, `read VAR`, `local VAR`, and similar state-mutating builtins should either get explicit support or conservatively mark the touched binding `Unknown`.
- The safest default for any builtin or grammar form that may mutate shell-local variable state is to invalidate affected bindings rather than keep propagating them.

## Recommendation

Implement narrow constant propagation for standalone static assignments only, with explicit scope boundaries and conservative flow rules.

That gets yah from:

```sh
VALS=--force && git push $VALS
```

being merely "dynamic, ask"

to being correctly understood as:

- `history-rewrite`
- `net-egress`

and therefore denied by policy, while still refusing to guess on anything that looks remotely like real shell computation.
