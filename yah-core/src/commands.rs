use crate::capability::Capability;
use std::collections::HashSet;

/// Network egress commands.
pub const NET_EGRESS_COMMANDS: &[&str] = &[
    "curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "telnet", "ftp",
    "ping", "traceroute", "dig", "nslookup", "host",
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
    "env", "nice", "timeout", "time", "ionice", "strace", "ltrace", "nohup", "setsid",
    "command", "builtin",
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
    if NET_INGRESS_COMMANDS.contains(&basename) && args.iter().any(|a| a == "-l" || a.contains('l'))
    {
        caps.insert(Capability::NetIngress);
    }

    // python -m http.server
    if matches!(basename, "python" | "python3") {
        if args.windows(2).any(|w| w[0] == "-m" && w[1] == "http.server") {
            caps.insert(Capability::NetIngress);
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
        if args.iter().any(|a| a.contains("u+s") || a.contains("4")) {
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
            let has_editable_dot =
                args.windows(2).any(|w| (w[0] == "-e" || w[0] == "--editable") && w[1] == ".");
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
    if args.is_empty() {
        return;
    }

    let subcommand = &args[0];
    match subcommand.as_str() {
        "push" => {
            if args.iter().any(|a| a == "--force" || a == "-f" || a == "--force-with-lease") {
                caps.insert(Capability::HistoryRewrite);
            }
            caps.insert(Capability::NetEgress);
        }
        "fetch" | "pull" | "clone" => {
            caps.insert(Capability::NetEgress);
        }
        "reset" => {
            if args.iter().any(|a| a == "--hard") {
                caps.insert(Capability::HistoryRewrite);
            }
        }
        "rebase" | "filter-branch" | "filter-repo" => {
            caps.insert(Capability::HistoryRewrite);
        }
        "clean" => {
            if args.iter().any(|a| a == "-f" || a == "-fd" || a == "-fdx" || a == "--force") {
                caps.insert(Capability::DeleteInsideRepo);
            }
        }
        _ => {}
    }
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
