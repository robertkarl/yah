use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use std::collections::HashMap;
use std::io::{self, BufRead};
use std::path::PathBuf;
use yah_core::{Capability, Classifier, Context};

#[derive(Parser)]
#[command(name = "yah", version, about = "Shell AST capability classifier")]
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
                    let cap_list: Vec<String> = sorted_caps(&caps)
                        .iter()
                        .map(|c| c.to_string())
                        .collect();
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
                    let (icon, desc) = cap_description(&cap);
                    println!("  {} {} — {}", icon, cap.to_string().red(), desc);
                }
            }
            println!();
            println!("{}", "Context:".bold().dimmed());
            println!("  cwd: {}", ctx.cwd.display());
            println!("  project_root: {}", ctx.project_root.display());
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
        if caps.is_empty() {
            println!("{}: {}", cmd.dimmed(), "clean".green());
        } else {
            let cap_list: Vec<String> = sorted_caps(caps).iter().map(|c| c.to_string()).collect();
            println!("{}: {}", cmd, cap_list.join(", ").red());
        }
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
        Capability::WriteInsideRepo => ("W+", "Writes to files inside the project"),
        Capability::WriteOutsideRepo => ("W!", "Writes to files outside the project"),
        Capability::DeleteInsideRepo => ("D+", "Deletes files inside the project"),
        Capability::DeleteOutsideRepo => ("D!", "Deletes files outside the project"),
        Capability::ReadSecretPath => ("S?", "Reads sensitive files (secrets, credentials)"),
        Capability::HistoryRewrite => ("H!", "Rewrites git history"),
        Capability::ExecDynamic => ("X?", "Executes dynamically constructed commands"),
        Capability::ProcessSignal => ("K!", "Sends signals to processes"),
        Capability::PrivilegeEscalation => ("P!", "Escalates privileges"),
    }
}
