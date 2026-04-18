use crate::capability::Capability;
use crate::commands;
use crate::context::Context;
use crate::paths;
use crate::wrappers;
use std::collections::HashSet;
use tree_sitter::Node;

/// Walk an AST node and collect capabilities.
pub fn walk_node(node: Node, source: &str, ctx: &Context) -> HashSet<Capability> {
    let mut caps = HashSet::new();

    // If the node is an ERROR node, fail closed
    if node.is_error() || node.kind() == "ERROR" {
        caps.insert(Capability::ExecDynamic);
        return caps;
    }

    match node.kind() {
        "program" => {
            // Walk all children — union of capabilities
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                caps.extend(walk_node(child, source, ctx));
            }
        }

        "command" => {
            caps.extend(classify_command_node(node, source, ctx));
        }

        "pipeline" => {
            // Union across all commands in the pipeline
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                caps.extend(walk_node(child, source, ctx));
            }
        }

        "list" => {
            // cmd1 && cmd2, cmd1 || cmd2, cmd1; cmd2
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                caps.extend(walk_node(child, source, ctx));
            }
        }

        "subshell" => {
            // (cmd) — union of inner commands
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                caps.extend(walk_node(child, source, ctx));
            }
        }

        "command_substitution" => {
            // $(cmd) or `cmd` — classify the inner command
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                caps.extend(walk_node(child, source, ctx));
            }
        }

        "process_substitution" => {
            // <(cmd) or >(cmd) — classify recursively
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                caps.extend(walk_node(child, source, ctx));
            }
        }

        "redirected_statement" => {
            // A command with redirections
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "file_redirect"
                    || child.kind() == "heredoc_redirect"
                    || child.kind() == "herestring_redirect"
                {
                    caps.extend(classify_redirect(child, source, ctx));
                } else {
                    caps.extend(walk_node(child, source, ctx));
                }
            }
        }

        "if_statement" | "while_statement" | "for_statement" | "case_statement" => {
            // Union across all branches
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                caps.extend(walk_node(child, source, ctx));
            }
        }

        "function_definition" => {
            // Classify the function body
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                caps.extend(walk_node(child, source, ctx));
            }
        }

        "compound_statement" => {
            // { cmd1; cmd2; } — union
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                caps.extend(walk_node(child, source, ctx));
            }
        }

        "negated_command" => {
            // ! cmd — classify the inner command
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                caps.extend(walk_node(child, source, ctx));
            }
        }

        "variable_assignment" => {
            // VAR=value — check if the value contains command substitution
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "command_substitution" || child.kind() == "process_substitution"
                {
                    caps.extend(walk_node(child, source, ctx));
                }
            }
        }

        "declaration_command" => {
            // export, local, declare, etc.
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                caps.extend(walk_node(child, source, ctx));
            }
        }

        _ => {
            // For any other node types, walk children
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                caps.extend(walk_node(child, source, ctx));
            }
        }
    }

    caps
}

/// Classify a single command node.
fn classify_command_node(node: Node, source: &str, ctx: &Context) -> HashSet<Capability> {
    let mut caps = HashSet::new();

    // Extract command name and arguments
    let (cmd_name, args) = extract_command_parts(node, source, ctx);

    let cmd_name = match cmd_name {
        Some(name) => name,
        None => {
            // Command name is dynamic (variable expansion in command position)
            caps.insert(Capability::ExecDynamic);
            return caps;
        }
    };

    // Check for wrapper unwrapping
    let (wrapper_names, inner_cmd, inner_args) = wrappers::unwrap_command(&cmd_name, &args);

    // Add capabilities for wrappers
    for wrapper in &wrapper_names {
        if commands::is_priv_esc_command(wrapper) {
            caps.insert(Capability::PrivilegeEscalation);
        }
    }

    // Classify the inner command
    if let Some(inner) = inner_cmd {
        let inner_args_owned: Vec<String> = inner_args.iter().map(|s| s.to_string()).collect();
        caps.extend(commands::classify_command(inner, &inner_args_owned));

        // Path-based classification for delete/write commands
        let basename = inner.rsplit('/').next().unwrap_or(inner);
        classify_paths_for_command(basename, &inner_args_owned, ctx, &mut caps);
    } else if !wrapper_names.is_empty() {
        // Wrappers with no inner command — the wrapper itself is the command
        // Already handled above
    }

    // Check for command substitution or variable expansion in arguments
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "command_substitution" || child.kind() == "process_substitution" {
            caps.extend(walk_node(child, source, ctx));
        }
        // Recurse into string nodes that may contain expansions
        if child.kind() == "string" || child.kind() == "raw_string" {
            let mut inner_cursor = child.walk();
            for inner_child in child.children(&mut inner_cursor) {
                if inner_child.kind() == "command_substitution" {
                    caps.extend(walk_node(inner_child, source, ctx));
                }
            }
        }
    }

    // Handle redirections that are direct children of the command
    let mut cursor2 = node.walk();
    for child in node.children(&mut cursor2) {
        if child.kind() == "file_redirect" {
            caps.extend(classify_redirect(child, source, ctx));
        }
    }

    caps
}

/// Extract command name and arguments from a command node.
/// Returns (Option<name>, args). Returns None for name if it's dynamic.
fn extract_command_parts(node: Node, source: &str, ctx: &Context) -> (Option<String>, Vec<String>) {
    let mut name: Option<String> = None;
    let mut args: Vec<String> = Vec::new();
    let mut first = true;

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "command_name" => {
                // The command name might be a simple word or a variable expansion
                let name_node = child.child(0);
                if let Some(n) = name_node {
                    match n.kind() {
                        "word" => {
                            name = Some(node_text(n, source).to_string());
                        }
                        "simple_expansion" | "expansion" => {
                            // Command name is $VAR or ${VAR} — try to resolve
                            let var_text = node_text(n, source);
                            let var_name = var_text
                                .trim_start_matches('$')
                                .trim_start_matches('{')
                                .trim_end_matches('}');
                            if let Some(val) = ctx.env.get(var_name) {
                                name = Some(val.clone());
                            } else {
                                return (None, vec![]); // Dynamic
                            }
                        }
                        _ => {
                            name = Some(node_text(n, source).to_string());
                        }
                    }
                }
            }
            "word" | "raw_string" | "concatenation" => {
                let text = resolve_word(child, source, ctx);
                if first && name.is_none() {
                    name = text;
                    first = false;
                } else if let Some(t) = text {
                    args.push(t);
                } else {
                    args.push(node_text(child, source).to_string());
                }
            }
            "string" => {
                let text = resolve_string(child, source, ctx);
                if let Some(t) = text {
                    args.push(t);
                } else {
                    args.push(node_text(child, source).to_string());
                }
            }
            "simple_expansion" | "expansion" => {
                let resolved = resolve_expansion(child, source, ctx);
                if let Some(val) = resolved {
                    args.push(val);
                } else {
                    // Unresolvable variable in argument position
                    args.push(node_text(child, source).to_string());
                }
            }
            "file_redirect" | "heredoc_redirect" | "herestring_redirect" => {
                // Handled separately
            }
            "command_substitution" | "process_substitution" => {
                // These are handled in the caller for capability extraction
                args.push(node_text(child, source).to_string());
            }
            _ => {
                if !child.is_named() {
                    continue;
                }
                // Other node types — add as-is
                let text = node_text(child, source);
                if !text.is_empty() {
                    args.push(text.to_string());
                }
            }
        }
    }

    (name, args)
}

/// Resolve a word node to a string, expanding variables where possible.
fn resolve_word(node: Node, source: &str, ctx: &Context) -> Option<String> {
    let text = node_text(node, source);

    // Simple case — no expansions
    if !text.contains('$') && !text.starts_with('~') {
        return Some(text.to_string());
    }

    // Tilde expansion
    if text.starts_with('~') && (text.len() == 1 || text.as_bytes().get(1) == Some(&b'/')) {
        let expanded = format!(
            "{}{}",
            ctx.home.to_str().unwrap_or("~"),
            &text[1..]
        );
        return Some(expanded);
    }

    // Try variable expansion
    expand_simple_vars(text, ctx)
}

/// Resolve a quoted string node.
fn resolve_string(node: Node, source: &str, ctx: &Context) -> Option<String> {
    let text = node_text(node, source);
    // Strip surrounding quotes
    if text.len() >= 2
        && ((text.starts_with('"') && text.ends_with('"'))
            || (text.starts_with('\'') && text.ends_with('\'')))
    {
        let inner = &text[1..text.len() - 1];
        if text.starts_with('\'') {
            // Single-quoted — no expansion
            return Some(inner.to_string());
        }
        // Double-quoted — expand variables
        return expand_simple_vars(inner, ctx);
    }
    Some(text.to_string())
}

/// Resolve a variable expansion node ($VAR or ${VAR}).
fn resolve_expansion(node: Node, source: &str, ctx: &Context) -> Option<String> {
    let text = node_text(node, source);
    let var_name = text
        .trim_start_matches('$')
        .trim_start_matches('{')
        .trim_end_matches('}');

    // Fail closed on complex expansions
    if var_name.contains(':')
        || var_name.contains('#')
        || var_name.contains('%')
        || var_name.contains('/')
        || var_name.contains('[')
    {
        return None;
    }

    if var_name == "HOME" {
        return Some(ctx.home.to_str().unwrap_or("").to_string());
    }

    ctx.env.get(var_name).cloned()
}

/// Expand simple $VAR and ${VAR} in a string. Returns None if any variable is unresolvable.
fn expand_simple_vars(text: &str, ctx: &Context) -> Option<String> {
    let mut result = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '$' {
            i += 1;
            if i >= chars.len() {
                return None;
            }
            let braced = chars[i] == '{';
            if braced {
                i += 1;
            }
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let var_name: String = chars[start..i].iter().collect();
            if braced {
                if i >= chars.len() || chars[i] != '}' {
                    return None;
                }
                i += 1;
            }
            if var_name.is_empty() {
                return None;
            }
            if var_name == "HOME" {
                result.push_str(ctx.home.to_str().unwrap_or(""));
            } else if let Some(val) = ctx.env.get(&var_name) {
                result.push_str(val);
            } else {
                return None;
            }
        } else if chars[i] == '\\' {
            // Skip escaped character
            i += 1;
            if i < chars.len() {
                result.push(chars[i]);
                i += 1;
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    Some(result)
}

/// Classify paths found in command arguments (for rm, cp, mv, etc.)
fn classify_paths_for_command(
    cmd: &str,
    args: &[String],
    ctx: &Context,
    caps: &mut HashSet<Capability>,
) {
    match cmd {
        "rm" | "rmdir" | "unlink" => {
            let path_args = extract_path_args(args);
            if path_args.is_empty() {
                // No path arguments found — could be using variables
                // Check if any arg looks like a variable
                let has_unresolved = args.iter().any(|a| a.contains('$'));
                if has_unresolved {
                    caps.insert(Capability::ExecDynamic);
                }
                return;
            }
            for path_str in &path_args {
                if let Some(normalized) = paths::normalize_path(path_str, ctx) {
                    if paths::is_sensitive_path(&normalized, ctx) {
                        caps.insert(Capability::ReadSecretPath);
                    }
                    if paths::is_inside_repo(&normalized, ctx) || paths::is_scratch_path(&normalized) {
                        caps.insert(Capability::DeleteInsideRepo);
                    } else {
                        caps.insert(Capability::DeleteOutsideRepo);
                    }
                } else {
                    // Can't resolve path — fail closed
                    caps.insert(Capability::DeleteOutsideRepo);
                    caps.insert(Capability::ExecDynamic);
                }
            }
        }
        "cp" | "mv" | "install" => {
            let path_args = extract_path_args(args);
            // The last path arg is the destination
            if let Some(dest) = path_args.last() {
                if let Some(normalized) = paths::normalize_path(dest, ctx) {
                    if paths::is_sensitive_path(&normalized, ctx) {
                        caps.insert(Capability::ReadSecretPath);
                    }
                    if paths::is_inside_repo(&normalized, ctx) || paths::is_scratch_path(&normalized) {
                        caps.insert(Capability::WriteInsideRepo);
                    } else {
                        caps.insert(Capability::WriteOutsideRepo);
                    }
                } else {
                    caps.insert(Capability::WriteOutsideRepo);
                    caps.insert(Capability::ExecDynamic);
                }
            }
            // Source paths for cp might be reading secrets
            for path_str in &path_args[..path_args.len().saturating_sub(1)] {
                if let Some(normalized) = paths::normalize_path(path_str, ctx) {
                    if paths::is_sensitive_path(&normalized, ctx) {
                        caps.insert(Capability::ReadSecretPath);
                    }
                }
            }
        }
        "cat" | "less" | "more" | "head" | "tail" | "grep" | "awk" | "sed" | "wc" | "sort"
        | "uniq" | "cut" | "tr" | "diff" | "strings" | "file" | "stat" | "xxd" | "od"
        | "hexdump" => {
            // Read-only commands — check for sensitive path access
            let path_args = extract_path_args(args);
            for path_str in &path_args {
                if let Some(normalized) = paths::normalize_path(path_str, ctx) {
                    if paths::is_sensitive_path(&normalized, ctx) {
                        caps.insert(Capability::ReadSecretPath);
                    }
                }
            }
        }
        "tee" => {
            // tee writes to files AND stdout
            let path_args = extract_path_args(args);
            for path_str in &path_args {
                if let Some(normalized) = paths::normalize_path(path_str, ctx) {
                    if paths::is_inside_repo(&normalized, ctx) || paths::is_scratch_path(&normalized) {
                        caps.insert(Capability::WriteInsideRepo);
                    } else {
                        caps.insert(Capability::WriteOutsideRepo);
                    }
                } else {
                    caps.insert(Capability::WriteOutsideRepo);
                }
            }
        }
        "chmod" | "chown" | "chgrp" => {
            // These modify file metadata
            let path_args = extract_path_args(args);
            for path_str in &path_args {
                if let Some(normalized) = paths::normalize_path(path_str, ctx) {
                    if paths::is_inside_repo(&normalized, ctx) || paths::is_scratch_path(&normalized) {
                        caps.insert(Capability::WriteInsideRepo);
                    } else {
                        caps.insert(Capability::WriteOutsideRepo);
                    }
                }
            }
        }
        "touch" | "mkdir" => {
            let path_args = extract_path_args(args);
            for path_str in &path_args {
                if let Some(normalized) = paths::normalize_path(path_str, ctx) {
                    if paths::is_inside_repo(&normalized, ctx) || paths::is_scratch_path(&normalized) {
                        caps.insert(Capability::WriteInsideRepo);
                    } else {
                        caps.insert(Capability::WriteOutsideRepo);
                    }
                } else {
                    caps.insert(Capability::WriteOutsideRepo);
                }
            }
        }
        "dd" => {
            for arg in args {
                if let Some(path) = arg.strip_prefix("of=") {
                    if let Some(normalized) = paths::normalize_path(path, ctx) {
                        if paths::is_inside_repo(&normalized, ctx) || paths::is_scratch_path(&normalized) {
                            caps.insert(Capability::WriteInsideRepo);
                        } else {
                            caps.insert(Capability::WriteOutsideRepo);
                        }
                    } else {
                        caps.insert(Capability::WriteOutsideRepo);
                    }
                }
                if let Some(path) = arg.strip_prefix("if=") {
                    if let Some(normalized) = paths::normalize_path(path, ctx) {
                        if paths::is_sensitive_path(&normalized, ctx) {
                            caps.insert(Capability::ReadSecretPath);
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

/// Extract path arguments from a command's argument list, skipping flags.
fn extract_path_args(args: &[String]) -> Vec<&str> {
    let mut paths = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--" {
            continue;
        }
        if arg.starts_with('-') {
            // Some flags take a value
            if arg.len() == 2 && arg != "-r" && arg != "-f" && arg != "-R" && arg != "-v" {
                // Potentially a flag with a value; be conservative and skip
            }
            continue;
        }
        paths.push(arg.as_str());
    }
    paths
}

/// Classify a file_redirect node.
fn classify_redirect(node: Node, source: &str, ctx: &Context) -> HashSet<Capability> {
    let mut caps = HashSet::new();
    let text = node_text(node, source);

    // Determine redirect type from the operator
    let is_write = text.starts_with('>')
        || text.contains(">>")
        || text.contains("&>")
        || text.contains(">&");
    let is_read = text.starts_with('<') && !text.starts_with("<<");

    // Find the target file path — it's usually the last child
    let target_node = node.child(node.child_count().saturating_sub(1));
    if let Some(target) = target_node {
        let target_text = node_text(target, source);
        // Try to resolve the path
        let target_str = if target_text.contains('$') {
            expand_simple_vars(&target_text, ctx)
        } else if target_text.starts_with('~') {
            Some(format!(
                "{}{}",
                ctx.home.to_str().unwrap_or("~"),
                &target_text[1..]
            ))
        } else {
            Some(target_text.to_string())
        };

        if let Some(path_str) = target_str {
            if let Some(normalized) = paths::normalize_path(&path_str, ctx) {
                if paths::is_dev_null(&normalized) {
                    return caps;
                }

                if is_write {
                    if paths::is_inside_repo(&normalized, ctx) || paths::is_scratch_path(&normalized) {
                        caps.insert(Capability::WriteInsideRepo);
                    } else {
                        caps.insert(Capability::WriteOutsideRepo);
                    }
                }

                if is_read && paths::is_sensitive_path(&normalized, ctx) {
                    caps.insert(Capability::ReadSecretPath);
                }
                if is_write && paths::is_sensitive_path(&normalized, ctx) {
                    caps.insert(Capability::ReadSecretPath);
                }
            } else {
                if is_write {
                    caps.insert(Capability::WriteOutsideRepo);
                }
            }
        } else {
            // Unresolvable variable in redirect target
            if is_write {
                caps.insert(Capability::WriteOutsideRepo);
                caps.insert(Capability::ExecDynamic);
            }
            if is_read {
                caps.insert(Capability::ExecDynamic);
            }
        }
    }

    caps
}

/// Get the text content of a node.
fn node_text<'a>(node: Node, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}
