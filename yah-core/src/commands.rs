use crate::capability::Capability;
use std::collections::HashSet;

/// Network egress commands.
pub const NET_EGRESS_COMMANDS: &[&str] = &[
    "curl",
    "wget",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "nc",
    "ncat",
    "netcat",
    "telnet",
    "ftp",
    "ping",
    "traceroute",
    "nmap",
    "dig",
    "nslookup",
    "host",
];

/// Network ingress commands.
pub const NET_INGRESS_COMMANDS: &[&str] = &["nc", "ncat", "netcat"];

/// Commands that signal processes.
pub const SIGNAL_COMMANDS: &[&str] = &["kill", "killall", "pkill"];

/// Privilege escalation commands.
pub const PRIV_ESC_COMMANDS: &[&str] = &["sudo", "doas", "su", "pkexec"];

/// Commands that exec dynamically.
pub const EXEC_DYNAMIC_COMMANDS: &[&str] = &["eval", "source"];

/// Wrapper commands that should be stripped before classifying the inner command.
pub const WRAPPER_COMMANDS: &[&str] = &[
    "env", "nice", "timeout", "time", "ionice", "strace", "ltrace", "nohup", "setsid", "command",
    "builtin",
];

/// Runtime exec commands (e.g., `python -c "..."`, `node -e "..."`).
pub const RUNTIME_EXEC: &[(&str, &[&str])] = &[
    ("python", &["-c"]),
    ("python3", &["-c"]),
    ("ruby", &["-e"]),
    ("perl", &["-e", "-E"]),
    ("node", &["-e", "--eval"]),
    ("php", &["-r"]),
];

/// Classify a command name with its arguments. Returns capabilities for the command itself
/// (not including path-based or redirect-based capabilities, which the walker handles).
pub fn classify_command(name: &str, args: &[String]) -> HashSet<Capability> {
    let mut caps = HashSet::new();
    let basename = name.rsplit('/').next().unwrap_or(name);

    // Privilege escalation
    if PRIV_ESC_COMMANDS.contains(&basename) {
        caps.insert(Capability::PrivilegeEscalation);
        // Inner command handled by wrapper unwrapping in walker
    }

    // Dynamic execution
    if EXEC_DYNAMIC_COMMANDS.contains(&basename) || basename == "." {
        caps.insert(Capability::ExecDynamic);
    }

    // bash -c / sh -c / zsh -c with arguments
    if matches!(basename, "bash" | "sh" | "zsh" | "dash" | "ksh") {
        if args.iter().any(|a| a == "-c") {
            caps.insert(Capability::ExecDynamic);
        }
    }

    // Network egress
    if NET_EGRESS_COMMANDS.contains(&basename) {
        caps.insert(Capability::NetEgress);
    }

    // Network ingress — nc/ncat with -l flag
    if NET_INGRESS_COMMANDS.contains(&basename) && args.iter().any(|a| is_netcat_listen_flag(a)) {
        caps.insert(Capability::NetIngress);
    }

    // python -m http.server
    if matches!(basename, "python" | "python3") {
        if args
            .windows(2)
            .any(|w| w[0] == "-m" && w[1] == "http.server")
        {
            caps.insert(Capability::NetIngress);
        }

        if let Some(pip_args) = python_module_args(args, "pip") {
            classify_package_install("pip", pip_args, &mut caps);
        }
    }

    // Process signaling
    if SIGNAL_COMMANDS.contains(&basename) {
        caps.insert(Capability::ProcessSignal);
    }

    // Runtime exec (python -c, node -e, etc.)
    for (cmd, flags) in RUNTIME_EXEC {
        if basename == *cmd && args.iter().any(|a| flags.contains(&a.as_str())) {
            caps.insert(Capability::ExecDynamic);
        }
    }

    // Package managers
    classify_package_install(basename, args, &mut caps);

    // Git-specific capabilities
    if basename == "git" {
        classify_git(args, &mut caps);
    }

    // rm / rmdir
    if basename == "rm" || basename == "rmdir" || basename == "unlink" {
        // Path-based delete classification happens in the walker.
        // If no path arguments are detectable, we still flag it.
        // The walker will refine to inside/outside based on paths.
    }

    // Encoding tricks — base64 decode piped to bash is caught by pipe analysis,
    // but standalone base64/xxd usage isn't itself dangerous.

    // xargs
    if basename == "xargs" {
        classify_xargs(args, &mut caps);
    }

    // chmod with setuid
    if basename == "chmod" {
        if args.iter().any(|a| chmod_sets_setuid(a)) {
            caps.insert(Capability::PrivilegeEscalation);
        }
    }

    // dd — can write anywhere
    if basename == "dd" {
        for arg in args {
            if arg.starts_with("of=") {
                // Path-based classification happens in walker via redirect analysis
                // but dd's of= is equivalent to a write redirect
            }
        }
    }

    caps
}

fn classify_package_install(basename: &str, args: &[String], caps: &mut HashSet<Capability>) {
    match basename {
        "pip" | "pip3" => {
            if !args.iter().any(|a| a == "install") {
                return;
            }
            // Safe: --target to a local dir, -e . (editable install of current project)
            let has_target = args.windows(2).any(|w| w[0] == "--target" || w[0] == "-t");
            let has_editable_dot = args
                .windows(2)
                .any(|w| (w[0] == "-e" || w[0] == "--editable") && w[1] == ".");
            if has_target || has_editable_dot {
                return;
            }
            caps.insert(Capability::PackageInstall);
        }
        "npm" | "npx" | "yarn" | "pnpm" | "bun" => {
            if args.first().map(|a| a.as_str()) == Some("install")
                || args.first().map(|a| a.as_str()) == Some("add")
                || args.first().map(|a| a.as_str()) == Some("i")
            {
                // npm install with no args (from lockfile) or with -g/--global
                let is_global = args.iter().any(|a| a == "-g" || a == "--global");
                if is_global {
                    caps.insert(Capability::PackageInstall);
                }
                // npm install <package> (adding a new dep)
                let has_package = args[1..].iter().any(|a| !a.starts_with('-'));
                if has_package {
                    caps.insert(Capability::PackageInstall);
                }
            }
        }
        "cargo" => {
            if args.first().map(|a| a.as_str()) == Some("install") {
                caps.insert(Capability::PackageInstall);
            }
        }
        "gem" => {
            if args.first().map(|a| a.as_str()) == Some("install") {
                caps.insert(Capability::PackageInstall);
            }
        }
        "go" => {
            if args.first().map(|a| a.as_str()) == Some("install") {
                caps.insert(Capability::PackageInstall);
            }
        }
        "brew" | "apt" | "apt-get" | "dnf" | "yum" | "pacman" | "apk" => {
            if args.iter().any(|a| a == "install" || a == "-S") {
                caps.insert(Capability::PackageInstall);
            }
        }
        _ => {}
    }
}

fn classify_git(args: &[String], caps: &mut HashSet<Capability>) {
    let Some((subcommand, subargs)) = git_subcommand_args(args) else {
        return;
    };

    let has_dynamic_args = subargs.iter().any(|arg| git_arg_is_dynamic(arg));
    match subcommand {
        "push" => {
            if has_dynamic_args {
                caps.insert(Capability::ExecDynamic);
            }
            if subargs
                .iter()
                .any(|a| a == "--force" || a == "-f" || a == "--force-with-lease")
            {
                caps.insert(Capability::HistoryRewrite);
            }
            caps.insert(Capability::NetEgress);
        }
        "fetch" | "pull" | "clone" => {
            caps.insert(Capability::NetEgress);
        }
        "reset" => {
            if has_dynamic_args {
                caps.insert(Capability::ExecDynamic);
            }
            if subargs.iter().any(|a| a == "--hard") {
                caps.insert(Capability::HistoryRewrite);
            }
        }
        "rebase" | "filter-branch" | "filter-repo" => {
            if has_dynamic_args {
                caps.insert(Capability::ExecDynamic);
            }
            caps.insert(Capability::HistoryRewrite);
        }
        "commit" => {
            if has_dynamic_args {
                caps.insert(Capability::ExecDynamic);
            }
            if subargs.iter().any(|a| a == "--amend") {
                caps.insert(Capability::HistoryRewrite);
            }
        }
        "clean" => {
            if has_dynamic_args {
                caps.insert(Capability::ExecDynamic);
            }
            if subargs
                .iter()
                .any(|a| a == "-f" || a == "-fd" || a == "-fdx" || a == "--force")
            {
                caps.insert(Capability::DeleteInsideRepo);
            }
        }
        "remote" => classify_git_remote(subargs, caps),
        "config" => classify_git_config(subargs, caps),
        _ => {}
    }
}

fn git_arg_is_dynamic(arg: &str) -> bool {
    arg.contains('$')
        || arg.contains("`")
        || arg.contains("$(")
        || arg.contains("<(")
        || arg.contains(">(")
}

fn git_subcommand_args(args: &[String]) -> Option<(&str, &[String])> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if !arg.starts_with('-') {
            return Some((arg, &args[i + 1..]));
        }

        if git_option_takes_value(arg) {
            i += 2;
            continue;
        }

        i += 1;
    }

    None
}

fn git_option_takes_value(arg: &str) -> bool {
    matches!(
        arg,
        "-C" | "--git-dir"
            | "--work-tree"
            | "--namespace"
            | "--super-prefix"
            | "--exec-path"
            | "--config-env"
    ) || arg == "-c"
        || arg.starts_with("-c")
        || arg.starts_with("--git-dir=")
        || arg.starts_with("--work-tree=")
        || arg.starts_with("--namespace=")
        || arg.starts_with("--super-prefix=")
        || arg.starts_with("--exec-path=")
        || arg.starts_with("--config-env=")
}

fn classify_git_remote(args: &[String], caps: &mut HashSet<Capability>) {
    let Some((action, action_args)) = first_non_flag_arg(args) else {
        return;
    };

    if action_args.iter().any(|arg| git_arg_is_dynamic(arg)) {
        caps.insert(Capability::ExecDynamic);
    }

    match action.as_str() {
        "add" | "rename" | "remove" | "rm" | "set-head" | "set-branches" | "set-url" => {
            caps.insert(Capability::GitRemoteModify);
        }
        _ => {}
    }

    if action == "add"
        && action_args
            .iter()
            .any(|arg| arg == "-f" || arg == "--fetch")
    {
        caps.insert(Capability::NetEgress);
    }
}

fn classify_git_config(args: &[String], caps: &mut HashSet<Capability>) {
    let mut i = 0;
    let mut mutates = false;

    while i < args.len() {
        let arg = args[i].as_str();
        if !arg.starts_with('-') {
            break;
        }

        if matches!(
            arg,
            "--add"
                | "--replace-all"
                | "--unset"
                | "--unset-all"
                | "--remove-section"
                | "--rename-section"
                | "--edit"
        ) {
            mutates = true;
        }

        if git_config_option_takes_value(arg) {
            i += 2;
        } else {
            i += 1;
        }
    }

    let Some(key) = args.get(i).map(|s| s.as_str()) else {
        return;
    };

    if !key.starts_with("remote.") {
        return;
    }

    let trailing = &args[i + 1..];
    if trailing.iter().any(|arg| git_arg_is_dynamic(arg)) {
        caps.insert(Capability::ExecDynamic);
    }

    if mutates || !trailing.is_empty() {
        caps.insert(Capability::GitRemoteModify);
    }
}

fn git_config_option_takes_value(arg: &str) -> bool {
    matches!(arg, "-f" | "--file" | "--blob" | "--type" | "--default")
        || arg.starts_with("--file=")
        || arg.starts_with("--blob=")
        || arg.starts_with("--type=")
        || arg.starts_with("--default=")
}

fn first_non_flag_arg(args: &[String]) -> Option<(String, &[String])> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if !arg.starts_with('-') {
            return Some((arg.to_string(), &args[i + 1..]));
        }

        if git_remote_option_takes_value(arg) {
            i += 2;
        } else {
            i += 1;
        }
    }

    None
}

fn git_remote_option_takes_value(arg: &str) -> bool {
    matches!(arg, "-t" | "-m")
}

fn classify_xargs(args: &[String], caps: &mut HashSet<Capability>) {
    // Find the command that xargs will execute
    // xargs [options] command [initial-arguments]
    // Skip option flags to find the actual command
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg.starts_with('-') {
            // Some xargs flags take a value
            if matches!(arg.as_str(), "-I" | "-L" | "-n" | "-P" | "-d" | "-E" | "-s") {
                i += 1; // skip the value
            }
            i += 1;
            continue;
        }
        // Found the command
        let basename = arg.rsplit('/').next().unwrap_or(arg);
        if basename == "rm" || basename == "rmdir" || basename == "unlink" {
            // Can't determine paths — emit both
            caps.insert(Capability::DeleteInsideRepo);
            caps.insert(Capability::DeleteOutsideRepo);
        }
        // Classify inner command with unknown args
        let inner_caps = classify_command(basename, &[]);
        caps.extend(inner_caps);
        return;
    }
    // xargs with no command defaults to echo — harmless
}

fn is_netcat_listen_flag(arg: &str) -> bool {
    arg == "-l"
        || arg == "--listen"
        || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('l'))
}

fn python_module_args<'a>(args: &'a [String], module: &str) -> Option<&'a [String]> {
    args.windows(2)
        .position(|w| w[0] == "-m" && w[1] == module)
        .map(|idx| &args[idx + 2..])
}

fn chmod_sets_setuid(arg: &str) -> bool {
    if arg.chars().all(|c| matches!(c, '0'..='7')) {
        let mode = arg.trim_start_matches('0');
        if mode.len() >= 4 {
            let special = mode.as_bytes()[mode.len() - 4] as char;
            return matches!(special, '4' | '5' | '6' | '7');
        }
        return false;
    }

    for clause in arg.split(',') {
        if let Some((who, perms)) = clause.split_once('+') {
            if perms.contains('s') && (who.is_empty() || who.contains('u') || who.contains('a')) {
                return true;
            }
        }
        if let Some((who, perms)) = clause.split_once('=') {
            if perms.contains('s') && (who.is_empty() || who.contains('u') || who.contains('a')) {
                return true;
            }
        }
    }

    false
}

/// Check if a command name is a known wrapper that should be unwrapped.
pub fn is_wrapper_command(name: &str) -> bool {
    let basename = name.rsplit('/').next().unwrap_or(name);
    WRAPPER_COMMANDS.contains(&basename) || PRIV_ESC_COMMANDS.contains(&basename)
}

/// Check if a command name is a privilege escalation wrapper.
pub fn is_priv_esc_command(name: &str) -> bool {
    let basename = name.rsplit('/').next().unwrap_or(name);
    PRIV_ESC_COMMANDS.contains(&basename)
}
