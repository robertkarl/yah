use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::{self, BufRead, Read as _};
use std::path::PathBuf;
use yah_core::{Capability, Classifier, Context};

#[derive(Parser)]
#[command(
    name = "yah",
    version,
    about = "Shell AST capability classifier",
    after_help = "\
Examples:
  yah classify \"curl example.com\"
  yah check \"ls\"
  yah explain \"sudo rm -rf /\"
  yah install-hook   # install as Claude Code hook

Recommended Claude Code setup:
  Don't run with --dangerously-ignore-permissions. Instead, add these
  to your .claude/settings.local.json under permissions.allow:

    \"Bash\",
    \"WebFetch\",
    \"WebSearch\"

  yah will block destructive git history modifications and ask about
  sensitive paths. yah uses a bash tree-sitter to inspect the command
  and understand what bash will actually run, with more detail than
  the crude prefixes that Claude Code permissions use.

Default policy (capability -> decision):
  allow:  write-inside-repo, delete-inside-repo, net-egress
  ask:    history-rewrite, and everything else (write-outside-repo, delete-outside-repo,
          read-secret-path, exec-dynamic, pipe-to-shell, git-remote-modify, privilege-escalation,
          net-ingress, process-signal, package-install)

Combination policy:
  deny:   history-rewrite + net-egress
  deny:   pipe-to-shell + net-egress

Command-specific overrides:
  deny:   pip/pip3 install (global), npm/yarn/pnpm install -g
  ask:    ssh/scp/sftp to sensitive hosts (192.168.50.57)

To change the defaults, edit capability_policy_rules() and
command_policy_override() in yah-cli/src/main.rs and rebuild
with `cargo install --path yah-cli`."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Override the current working directory
    #[arg(long, global = true)]
    cwd: Option<PathBuf>,

    /// Override the project root directory
    #[arg(long, global = true)]
    project_root: Option<PathBuf>,

    /// Output format
    #[arg(long, global = true, default_value = "auto")]
    color: ColorMode,

    /// JSON output
    #[arg(long, global = true)]
    json: bool,

    /// Suppress all output except errors
    #[arg(long, global = true)]
    quiet: bool,
}

#[derive(Clone, ValueEnum)]
enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand)]
enum Commands {
    /// Classify a shell command and report its capabilities
    Classify {
        /// The command to classify (reads from stdin if not provided)
        command: Option<String>,
    },
    /// Check if a command requires any capabilities (exit 0 = safe, 1 = capabilities detected)
    Check {
        /// The command to check
        command: String,
    },
    /// Explain a command's capabilities in human-readable form
    Explain {
        /// The command to explain
        command: String,
    },
    /// Run as a Claude Code PreToolUse hook (reads hook JSON from stdin)
    Hook,
    /// Install yah as a Claude Code PreToolUse hook
    InstallHook,
    /// Remove yah from Claude Code hooks
    UninstallHook,
}

fn main() {
    let cli = Cli::parse();

    // Set up color mode
    match cli.color {
        ColorMode::Always => colored::control::set_override(true),
        ColorMode::Never => colored::control::set_override(false),
        ColorMode::Auto => {} // colored handles this
    }

    let ctx = build_context(cli.cwd, cli.project_root);
    let mut classifier = Classifier::new();

    match cli.command {
        Commands::Classify { command } => {
            if let Some(cmd) = command {
                let caps = classifier.classify(&cmd, &ctx);
                output_classify(&cmd, &caps, cli.json, cli.quiet);
            } else {
                // Read from stdin, one command per line
                let stdin = io::stdin();
                for line in stdin.lock().lines() {
                    match line {
                        Ok(cmd) => {
                            let cmd = cmd.trim().to_string();
                            if cmd.is_empty() {
                                continue;
                            }
                            let caps = classifier.classify(&cmd, &ctx);
                            output_classify(&cmd, &caps, cli.json, cli.quiet);
                        }
                        Err(e) => {
                            eprintln!("error reading stdin: {}", e);
                            std::process::exit(2);
                        }
                    }
                }
            }
        }

        Commands::Check { command } => {
            let caps = classifier.classify(&command, &ctx);
            if caps.is_empty() {
                if !cli.quiet {
                    println!("{}", "clean".green());
                }
                std::process::exit(0);
            } else {
                if !cli.quiet {
                    let cap_list: Vec<String> =
                        sorted_caps(&caps).iter().map(|c| c.to_string()).collect();
                    println!("{}: {}", "capabilities".red(), cap_list.join(", "));
                }
                std::process::exit(1);
            }
        }

        Commands::Explain { command } => {
            let caps = classifier.classify(&command, &ctx);
            println!("{}", "Command:".bold());
            println!("  {}", command);
            println!();

            if caps.is_empty() {
                println!(
                    "{} {}",
                    "Result:".bold(),
                    "No sensitive capabilities detected.".green()
                );
            } else {
                println!("{}", "Capabilities:".bold());
                for cap in sorted_caps(&caps) {
                    let (_, desc) = cap_description(&cap);
                    println!("  {} — {}", cap.to_string().red(), desc);
                }
            }
            println!();
            println!("{}", "Context:".bold().dimmed());
            println!("  cwd: {}", ctx.cwd.display());
            println!("  project_root: {}", ctx.project_root.display());
        }

        Commands::Hook => {
            handle_hook(&ctx, &mut classifier);
        }

        Commands::InstallHook => {
            handle_install();
        }

        Commands::UninstallHook => {
            handle_uninstall();
        }
    }
}

fn build_context(cwd_override: Option<PathBuf>, root_override: Option<PathBuf>) -> Context {
    let cwd = cwd_override
        .map(|p| canonicalize_or_raw(p))
        .unwrap_or_else(|| {
            std::env::current_dir()
                .map(|p| canonicalize_or_raw(p))
                .unwrap_or_else(|_| PathBuf::from("/"))
        });

    let project_root = root_override
        .map(|p| canonicalize_or_raw(p))
        .unwrap_or_else(|| find_project_root(&cwd).unwrap_or_else(|| cwd.clone()));

    let home = dirs_or_env();

    let env: HashMap<String, String> = std::env::vars().collect();

    Context {
        cwd,
        project_root,
        home,
        env,
    }
}

fn canonicalize_or_raw(p: PathBuf) -> PathBuf {
    std::fs::canonicalize(&p).unwrap_or(p)
}

fn dirs_or_env() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/"))
}

/// Walk up from cwd looking for .git to find project root.
fn find_project_root(cwd: &PathBuf) -> Option<PathBuf> {
    let mut dir = cwd.as_path();
    loop {
        if dir.join(".git").exists() {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
}

fn output_classify(
    cmd: &str,
    caps: &std::collections::HashSet<Capability>,
    json: bool,
    quiet: bool,
) {
    if quiet && caps.is_empty() {
        return;
    }

    if json {
        let output = serde_json::json!({
            "command": cmd,
            "capabilities": sorted_caps(caps).iter().map(|c| c.to_string()).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string(&output).unwrap());
    } else if !quiet {
        println!("{} {}", "Command:".bold(), cmd);
        if caps.is_empty() {
            println!("  {} No capabilities detected.", "CLEAN".green().bold());
        } else {
            let sorted = sorted_caps(caps);
            for cap in &sorted {
                let (_, desc) = cap_description(cap);
                let decision = default_policy(cap);
                let policy_label = match decision {
                    PolicyDecision::Allow => "allow".green(),
                    PolicyDecision::Ask => "ask".yellow(),
                    PolicyDecision::Deny => "deny".red(),
                };
                println!("  {} — {} [{}]", cap.to_string().bold(), desc, policy_label);
            }

            let evaluation = evaluate_policy(caps);
            if evaluation.decision != PolicyDecision::Allow {
                let policy_label = match evaluation.decision {
                    PolicyDecision::Allow => "allow".green(),
                    PolicyDecision::Ask => "ask".yellow(),
                    PolicyDecision::Deny => "deny".red(),
                };
                println!(
                    "  {} — {} [{}]",
                    "overall policy".bold(),
                    evaluation.triggers.join(", "),
                    policy_label
                );
            }
        }
        println!();
    }
}

fn sorted_caps(caps: &std::collections::HashSet<Capability>) -> Vec<Capability> {
    let mut v: Vec<_> = caps.iter().cloned().collect();
    v.sort();
    v
}

fn cap_description(cap: &Capability) -> (&'static str, &'static str) {
    match cap {
        Capability::NetEgress => ("->", "Makes outbound network connections"),
        Capability::NetIngress => ("<-", "Listens for inbound network connections"),
        Capability::PipeToShell => ("|>", "Pipes data into a shell interpreter"),
        Capability::GitRemoteModify => ("Gr", "Modifies git remote configuration"),
        Capability::WriteInsideRepo => ("W+", "Writes to files inside the project"),
        Capability::WriteOutsideRepo => ("W!", "Writes to files outside the project"),
        Capability::DeleteInsideRepo => ("D+", "Deletes files inside the project"),
        Capability::DeleteOutsideRepo => ("D!", "Deletes files outside the project"),
        Capability::ReadSecretPath => ("S?", "Reads sensitive files (secrets, credentials)"),
        Capability::HistoryRewrite => ("H!", "Rewrites git history"),
        Capability::ExecDynamic => ("X?", "Executes dynamically constructed commands"),
        Capability::ProcessSignal => ("K!", "Sends signals to processes"),
        Capability::PrivilegeEscalation => ("P!", "Escalates privileges"),
        Capability::PackageInstall => ("Pk", "Installs system/global packages"),
    }
}

/// Handle the `yah hook` subcommand — Claude Code PreToolUse hook.
///
/// Reads hook JSON from stdin, classifies the command if it's a Bash tool call,
/// and outputs the appropriate hook response JSON.
fn handle_hook(ctx: &Context, classifier: &mut Classifier) {
    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() {
        std::process::exit(0); // No input, allow
    }

    let hook_input: serde_json::Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(_) => {
            // Can't parse hook input — allow (don't block on our failure)
            std::process::exit(0);
        }
    };

    // Only classify Bash tool calls
    let tool_name = hook_input["tool_name"].as_str().unwrap_or("");
    if tool_name != "Bash" {
        // Not a Bash call — allow
        std::process::exit(0);
    }

    let command = match hook_input["tool_input"]["command"].as_str() {
        Some(cmd) => cmd,
        None => {
            std::process::exit(0);
        }
    };

    let caps = classifier.classify(command, ctx);

    // Command-specific policy overrides (checked before capability-based policy)
    if let Some(override_decision) = command_policy_override(command) {
        match override_decision {
            (PolicyDecision::Allow, _) => {
                std::process::exit(0);
            }
            (PolicyDecision::Ask, reason) => {
                let response = serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "ask",
                        "permissionDecisionReason": reason,
                    }
                });
                println!("{}", serde_json::to_string(&response).unwrap());
                std::process::exit(0);
            }
            (PolicyDecision::Deny, reason) => {
                let response = serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": reason,
                    }
                });
                println!("{}", serde_json::to_string(&response).unwrap());
                std::process::exit(0);
            }
        }
    }

    if caps.is_empty() {
        // Clean command — allow silently
        std::process::exit(0);
    }

    // Apply default policy: capability -> allow / ask / deny
    let evaluation = evaluate_policy(&caps);

    match evaluation.decision {
        PolicyDecision::Allow => {
            // All capabilities are in the allow set — pass silently
            std::process::exit(0);
        }
        PolicyDecision::Ask => {
            let reason = format_ask_reason(&caps, &evaluation);
            let response = serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": reason,
                }
            });
            println!("{}", serde_json::to_string(&response).unwrap());
            std::process::exit(0);
        }
        PolicyDecision::Deny => {
            let reason = format_deny_reason(&caps, &evaluation);
            let response = serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            });
            println!("{}", serde_json::to_string(&response).unwrap());
            std::process::exit(0);
        }
    }
}

fn format_deny_reason(
    caps: &std::collections::HashSet<Capability>,
    evaluation: &PolicyEvaluation,
) -> String {
    let all: Vec<String> = sorted_caps(caps).iter().map(|c| c.to_string()).collect();

    format!(
        "yah blocked this command. Capabilities detected: [{}]. \
         Denied by policy: [{}]. \
         Edit capability_policy_rules() in yah-cli/src/main.rs to change. \
         Run `yah --help` to see current policy.",
        all.join(", "),
        evaluation.triggers.join(", "),
    )
}

fn format_ask_reason(
    caps: &std::collections::HashSet<Capability>,
    evaluation: &PolicyEvaluation,
) -> String {
    let all: Vec<String> = sorted_caps(caps).iter().map(|c| c.to_string()).collect();

    format!(
        "yah detected capabilities: [{}]. \
         Needs approval: [{}]. \
         Run `yah --help` to see current policy.",
        all.join(", "),
        evaluation.triggers.join(", "),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PolicyDecision {
    Allow,
    Ask,
    Deny,
}

#[derive(Debug, Clone)]
struct CapabilityRule {
    all_of: BTreeSet<Capability>,
    none_of: BTreeSet<Capability>,
    decision: PolicyDecision,
    reason: String,
}

impl CapabilityRule {
    fn matches(&self, caps: &HashSet<Capability>) -> bool {
        self.all_of.iter().all(|cap| caps.contains(cap))
            && self.none_of.iter().all(|cap| !caps.contains(cap))
    }
}

#[derive(Debug)]
struct PolicyEvaluation {
    decision: PolicyDecision,
    triggers: Vec<String>,
}

/// Compile-time capability policy rules.
///
/// This keeps the "edit the source and rebuild" workflow while making
/// multi-capability policy combinations first-class data rather than
/// one-off conditionals.
fn capability_policy_rules() -> Vec<CapabilityRule> {
    vec![
        CapabilityRule {
            all_of: cap_set([Capability::WriteInsideRepo]),
            none_of: cap_set([]),
            decision: PolicyDecision::Allow,
            reason: "write-inside-repo".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::DeleteInsideRepo]),
            none_of: cap_set([]),
            decision: PolicyDecision::Allow,
            reason: "delete-inside-repo".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::NetEgress]),
            none_of: cap_set([Capability::HistoryRewrite]),
            decision: PolicyDecision::Allow,
            reason: "net-egress".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::HistoryRewrite]),
            none_of: cap_set([Capability::NetEgress]),
            decision: PolicyDecision::Ask,
            reason: "history-rewrite".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::NetIngress]),
            none_of: cap_set([]),
            decision: PolicyDecision::Ask,
            reason: "net-ingress".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::PipeToShell]),
            none_of: cap_set([Capability::NetEgress]),
            decision: PolicyDecision::Ask,
            reason: "pipe-to-shell".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::GitRemoteModify]),
            none_of: cap_set([]),
            decision: PolicyDecision::Ask,
            reason: "git-remote-modify".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::WriteOutsideRepo]),
            none_of: cap_set([]),
            decision: PolicyDecision::Ask,
            reason: "write-outside-repo".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::DeleteOutsideRepo]),
            none_of: cap_set([]),
            decision: PolicyDecision::Ask,
            reason: "delete-outside-repo".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::ReadSecretPath]),
            none_of: cap_set([]),
            decision: PolicyDecision::Ask,
            reason: "read-secret-path".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::ExecDynamic]),
            none_of: cap_set([]),
            decision: PolicyDecision::Ask,
            reason: "exec-dynamic".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::ProcessSignal]),
            none_of: cap_set([]),
            decision: PolicyDecision::Ask,
            reason: "process-signal".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::PrivilegeEscalation]),
            none_of: cap_set([]),
            decision: PolicyDecision::Ask,
            reason: "privilege-escalation".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::PackageInstall]),
            none_of: cap_set([]),
            decision: PolicyDecision::Ask,
            reason: "package-install".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::HistoryRewrite, Capability::NetEgress]),
            none_of: cap_set([]),
            decision: PolicyDecision::Deny,
            reason: "history-rewrite + net-egress".to_string(),
        },
        CapabilityRule {
            all_of: cap_set([Capability::PipeToShell, Capability::NetEgress]),
            none_of: cap_set([]),
            decision: PolicyDecision::Deny,
            reason: "pipe-to-shell + net-egress".to_string(),
        },
    ]
}

fn cap_set<const N: usize>(caps: [Capability; N]) -> BTreeSet<Capability> {
    caps.into_iter().collect()
}

/// Evaluate the compile-time capability rules.
///
/// deny > ask > allow — the most restrictive decision wins.
fn evaluate_policy(caps: &HashSet<Capability>) -> PolicyEvaluation {
    let matches: Vec<CapabilityRule> = capability_policy_rules()
        .into_iter()
        .filter(|rule| rule.matches(caps))
        .collect();

    let decision = matches
        .iter()
        .map(|rule| rule.decision)
        .max()
        .unwrap_or(PolicyDecision::Allow);

    let triggers: Vec<String> = matches
        .iter()
        .filter(|rule| rule.decision == decision)
        .map(|rule| rule.reason.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    PolicyEvaluation { decision, triggers }
}

/// Command-specific policy overrides.
/// Returns Some((decision, reason)) if the command matches a specific rule.
/// These are checked before capability-based policy and take precedence.
fn command_policy_override(command: &str) -> Option<(PolicyDecision, String)> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let (basename, args) = extract_override_command(&parts)
        .map(|(name, args)| (name.rsplit('/').next().unwrap_or(name), args))
        .unwrap_or_else(|| (parts[0].rsplit('/').next().unwrap_or(parts[0]), &parts[1..]));

    // Deny global pip/npm installs — these write outside the project
    // and Claude tries them constantly
    if let Some(pip_args) = override_pip_install_args(basename, args) {
        let has_target = pip_args
            .windows(2)
            .any(|w| w[0] == "--target" || w[0] == "-t");
        let has_editable_dot = pip_args
            .windows(2)
            .any(|w| (w[0] == "-e" || w[0] == "--editable") && w[1] == ".");
        if !has_target && !has_editable_dot {
            return Some((
                PolicyDecision::Deny,
                "yah blocked global pip install. Use a virtualenv, \
                 or `pip install --target ./local_deps` instead."
                    .to_string(),
            ));
        }
    }
    if matches!(basename, "npm" | "npx" | "yarn" | "pnpm" | "bun")
        && args.iter().any(|&p| p == "-g" || p == "--global")
    {
        return Some((
            PolicyDecision::Deny,
            "yah blocked global npm install. Install locally \
             with `npm install <pkg>` (no -g) instead."
                .to_string(),
        ));
    }

    // Ask before SSH/SCP to sensitive hosts
    const SENSITIVE_HOSTS: &[&str] = &["192.168.50.57"];

    if matches!(basename, "ssh" | "scp" | "sftp") {
        for part in args {
            // Skip flags
            if part.starts_with('-') {
                continue;
            }
            // Check for user@host or bare host, with optional :port
            let host_part = if let Some((_user, rest)) = part.split_once('@') {
                rest
            } else {
                part
            };
            // Strip :port or trailing path (scp uses host:path)
            let host = host_part.split(':').next().unwrap_or(host_part);
            if SENSITIVE_HOSTS.contains(&host) {
                return Some((
                    PolicyDecision::Ask,
                    format!(
                        "yah detected SSH/SCP to sensitive host {}. \
                         This host is in your protected hosts list.",
                        host
                    ),
                ));
            }
        }
    }

    None
}

fn default_policy(cap: &Capability) -> PolicyDecision {
    let singleton: HashSet<Capability> = std::iter::once(*cap).collect();
    evaluate_policy(&singleton).decision
}

fn extract_override_command<'a>(parts: &'a [&'a str]) -> Option<(&'a str, &'a [&'a str])> {
    let mut current = parts;

    loop {
        let (name, args) = current.split_first()?;
        let basename = name.rsplit('/').next().unwrap_or(name);

        match basename {
            "sudo" | "doas" | "su" | "pkexec" => {
                let idx = skip_priv_esc_args_for_override(basename, args)?;
                current = &args[idx..];
            }
            "env" => {
                let idx = skip_wrapper_args_for_override("env", args)?;
                current = &args[idx..];
            }
            "timeout" | "nice" | "time" | "nohup" | "setsid" | "command" | "builtin" | "ionice"
            | "strace" | "ltrace" => {
                let idx = skip_wrapper_args_for_override(basename, args)?;
                current = &args[idx..];
            }
            _ => return Some((*name, args)),
        }
    }
}

fn skip_priv_esc_args_for_override(wrapper: &str, args: &[&str]) -> Option<usize> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--" {
            i += 1;
            break;
        }
        if !arg.starts_with('-') {
            if wrapper == "sudo" && arg.contains('=') && !arg.starts_with('=') {
                i += 1;
                continue;
            }
            break;
        }
        if wrapper == "sudo" && matches!(arg, "-u" | "-g" | "-C" | "-D" | "-R" | "-T") {
            i += 2;
            continue;
        }
        i += 1;
    }

    (i < args.len()).then_some(i)
}

fn skip_wrapper_args_for_override(wrapper: &str, args: &[&str]) -> Option<usize> {
    let mut i = 0;

    match wrapper {
        "env" => {
            while i < args.len() {
                let arg = args[i];
                if arg == "--" {
                    i += 1;
                    break;
                }
                if arg.starts_with('-') {
                    if arg == "-u" || arg == "--unset" {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    continue;
                }
                if arg.contains('=') && !arg.starts_with('=') {
                    i += 1;
                    continue;
                }
                break;
            }
        }
        "timeout" => {
            while i < args.len() && args[i].starts_with('-') {
                if matches!(args[i], "--signal" | "-s" | "-k") {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            if i < args.len() {
                i += 1;
            }
        }
        "nice" => {
            while i < args.len() && args[i].starts_with('-') {
                if matches!(args[i], "-n" | "--adjustment") {
                    i += 2;
                } else {
                    i += 1;
                }
            }
        }
        "time" | "nohup" | "setsid" | "command" | "builtin" => {
            while i < args.len() && args[i].starts_with('-') {
                i += 1;
            }
        }
        "ionice" => {
            while i < args.len() && args[i].starts_with('-') {
                if matches!(args[i], "-c" | "-n" | "-p" | "--class" | "--classdata") {
                    i += 2;
                } else {
                    i += 1;
                }
            }
        }
        "strace" | "ltrace" => {
            while i < args.len() && args[i].starts_with('-') {
                if matches!(args[i], "-e" | "-o" | "-p" | "-s" | "-a" | "-f" | "-ff") {
                    i += 2;
                } else {
                    i += 1;
                }
            }
        }
        _ => {}
    }

    (i < args.len()).then_some(i)
}

fn override_pip_install_args<'a>(basename: &str, args: &'a [&'a str]) -> Option<&'a [&'a str]> {
    if matches!(basename, "pip" | "pip3") && args.iter().any(|&arg| arg == "install") {
        return Some(args);
    }

    if matches!(basename, "python" | "python3") {
        if let Some(idx) = args.windows(2).position(|w| w[0] == "-m" && w[1] == "pip") {
            let pip_args = &args[idx + 2..];
            if pip_args.iter().any(|&arg| arg == "install") {
                return Some(pip_args);
            }
        }
    }

    None
}

/// Handle `yah install` — write hook config to ~/.claude/settings.json.
fn handle_install() {
    let yah_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "yah".to_string());

    let settings_path = dirs_or_env().join(".claude").join("settings.json");

    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = std::fs::read_to_string(&settings_path).unwrap_or_else(|e| {
            eprintln!("error reading {}: {}", settings_path.display(), e);
            std::process::exit(1);
        });
        serde_json::from_str(&content).unwrap_or_else(|e| {
            eprintln!("error parsing {}: {}", settings_path.display(), e);
            std::process::exit(1);
        })
    } else {
        serde_json::json!({})
    };

    let hook_entry = serde_json::json!({
        "matcher": "Bash",
        "hooks": [{
            "type": "command",
            "command": format!("{} hook", yah_path),
        }]
    });

    // Check if hooks.PreToolUse already has a yah entry
    let hooks = settings
        .as_object_mut()
        .unwrap()
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let pre_tool_use = hooks
        .as_object_mut()
        .unwrap()
        .entry("PreToolUse")
        .or_insert_with(|| serde_json::json!([]));

    let arr = pre_tool_use.as_array_mut().unwrap();

    // Remove any existing yah entries
    arr.retain(|entry| {
        let hooks = entry.get("hooks").and_then(|h| h.as_array());
        if let Some(hooks) = hooks {
            !hooks.iter().any(|h| {
                h.get("command")
                    .and_then(|c| c.as_str())
                    .map(|c| c.contains("yah"))
                    .unwrap_or(false)
            })
        } else {
            true
        }
    });

    arr.push(hook_entry);

    // Ensure parent directory exists
    if let Some(parent) = settings_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let content = serde_json::to_string_pretty(&settings).unwrap();
    std::fs::write(&settings_path, content).unwrap_or_else(|e| {
        eprintln!("error writing {}: {}", settings_path.display(), e);
        std::process::exit(1);
    });

    println!(
        "{} yah hook installed to {}",
        "OK".green(),
        settings_path.display()
    );
    println!("  Bash commands will be classified before execution.");
    println!("  Commands with capabilities will prompt for confirmation.");
    println!();
    println!("  Run {} to remove.", "yah uninstall-hook".bold());
}

/// Handle `yah uninstall` — remove yah hook from ~/.claude/settings.json.
fn handle_uninstall() {
    let settings_path = dirs_or_env().join(".claude").join("settings.json");

    if !settings_path.exists() {
        println!("No settings file found at {}", settings_path.display());
        return;
    }

    let content = std::fs::read_to_string(&settings_path).unwrap_or_else(|e| {
        eprintln!("error reading {}: {}", settings_path.display(), e);
        std::process::exit(1);
    });

    let mut settings: serde_json::Value = serde_json::from_str(&content).unwrap_or_else(|e| {
        eprintln!("error parsing {}: {}", settings_path.display(), e);
        std::process::exit(1);
    });

    let removed = if let Some(hooks) = settings.get_mut("hooks") {
        if let Some(pre_tool_use) = hooks.get_mut("PreToolUse") {
            if let Some(arr) = pre_tool_use.as_array_mut() {
                let before = arr.len();
                arr.retain(|entry| {
                    let hooks = entry.get("hooks").and_then(|h| h.as_array());
                    if let Some(hooks) = hooks {
                        !hooks.iter().any(|h| {
                            h.get("command")
                                .and_then(|c| c.as_str())
                                .map(|c| c.contains("yah"))
                                .unwrap_or(false)
                        })
                    } else {
                        true
                    }
                });
                before != arr.len()
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    if removed {
        let content = serde_json::to_string_pretty(&settings).unwrap();
        std::fs::write(&settings_path, content).unwrap_or_else(|e| {
            eprintln!("error writing {}: {}", settings_path.display(), e);
            std::process::exit(1);
        });
        println!(
            "{} yah hook removed from {}",
            "OK".green(),
            settings_path.display()
        );
    } else {
        println!("No yah hook found in {}", settings_path.display());
    }
}
