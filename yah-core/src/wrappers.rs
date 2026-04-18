use crate::commands;

/// Given a command name and its arguments, unwrap wrapper commands to find the inner
/// command and its arguments. Returns (wrapper_capabilities, inner_command, inner_args).
///
/// For example: `sudo env FOO=bar rm -rf /tmp` ->
///   wrappers: ["sudo", "env"]
///   inner: "rm"
///   inner_args: ["-rf", "/tmp"]
pub fn unwrap_command<'a>(
    name: &'a str,
    args: &'a [String],
) -> (Vec<&'a str>, Option<&'a str>, Vec<&'a String>) {
    let mut wrappers = Vec::new();
    let mut current_name = name;
    let mut current_args: &[String] = args;

    loop {
        let basename = current_name.rsplit('/').next().unwrap_or(current_name);

        if commands::is_priv_esc_command(basename) {
            wrappers.push(current_name);
            // Skip flags (e.g., sudo -u user), find the inner command
            let inner = skip_flags(basename, current_args);
            if let Some((cmd_idx, _)) = inner {
                current_name = &current_args[cmd_idx];
                current_args = &current_args[cmd_idx + 1..];
                continue;
            }
            // No inner command found
            return (wrappers, None, vec![]);
        }

        if commands::WRAPPER_COMMANDS.contains(&basename) {
            wrappers.push(current_name);
            let inner = skip_wrapper_args(basename, current_args);
            if let Some((cmd_idx, _)) = inner {
                current_name = &current_args[cmd_idx];
                current_args = &current_args[cmd_idx + 1..];
                continue;
            }
            return (wrappers, None, vec![]);
        }

        // Not a wrapper — this is the real command
        return (wrappers, Some(current_name), current_args.iter().collect());
    }
}

/// Skip flags for privilege escalation commands to find the inner command index.
fn skip_flags<'a>(wrapper: &str, args: &'a [String]) -> Option<(usize, &'a str)> {
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" {
            i += 1;
            break;
        }
        if !arg.starts_with('-') {
            // For sudo, skip env-like assignments (VAR=val)
            if wrapper == "sudo" && arg.contains('=') && !arg.starts_with('=') {
                i += 1;
                continue;
            }
            break;
        }
        // sudo flags that take a value
        if wrapper == "sudo" && matches!(arg.as_str(), "-u" | "-g" | "-C" | "-D" | "-R" | "-T") {
            i += 2;
            continue;
        }
        i += 1;
    }
    if i < args.len() {
        Some((i, &args[i]))
    } else {
        None
    }
}

/// Skip arguments for wrapper commands (env, nice, timeout, etc.) to find the inner command.
fn skip_wrapper_args<'a>(wrapper: &str, args: &'a [String]) -> Option<(usize, &'a str)> {
    let mut i = 0;
    match wrapper {
        "env" => {
            // env skips: flags, VAR=val assignments
            while i < args.len() {
                let arg = &args[i];
                if arg == "--" {
                    i += 1;
                    break;
                }
                if arg.starts_with('-') {
                    // -u VAR takes a value
                    if arg == "-u" || arg == "--unset" {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    continue;
                }
                if arg.contains('=') && !arg.starts_with('=') {
                    // VAR=val assignment
                    i += 1;
                    continue;
                }
                break;
            }
        }
        "timeout" => {
            // timeout [options] DURATION command
            while i < args.len() && args[i].starts_with('-') {
                if args[i] == "--signal" || args[i] == "-s" || args[i] == "-k" {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            // Skip the duration argument
            if i < args.len() {
                i += 1;
            }
        }
        "nice" => {
            while i < args.len() && args[i].starts_with('-') {
                if args[i] == "-n" || args[i] == "--adjustment" {
                    i += 2;
                } else {
                    i += 1;
                }
            }
        }
        "time" | "nohup" | "setsid" | "command" | "builtin" => {
            // These just prefix the command directly (possibly with flags)
            while i < args.len() && args[i].starts_with('-') {
                i += 1;
            }
        }
        "ionice" => {
            while i < args.len() && args[i].starts_with('-') {
                if matches!(args[i].as_str(), "-c" | "-n" | "-p" | "--class" | "--classdata") {
                    i += 2;
                } else {
                    i += 1;
                }
            }
        }
        "strace" | "ltrace" => {
            while i < args.len() && args[i].starts_with('-') {
                if matches!(
                    args[i].as_str(),
                    "-e" | "-o" | "-p" | "-s" | "-a" | "-f" | "-ff"
                ) {
                    i += 2;
                } else {
                    i += 1;
                }
            }
        }
        _ => {}
    }

    if i < args.len() {
        Some((i, &args[i]))
    } else {
        None
    }
}
