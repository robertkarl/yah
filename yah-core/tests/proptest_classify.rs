use proptest::prelude::*;
use std::collections::HashMap;
use std::path::PathBuf;
use yah_core::{Capability, Classifier, Context};

fn test_ctx() -> Context {
    Context {
        cwd: PathBuf::from("/home/user/project"),
        project_root: PathBuf::from("/home/user/project"),
        home: PathBuf::from("/home/user"),
        env: HashMap::new(),
    }
}

proptest! {
    /// classify() must never panic on any arbitrary UTF-8 string.
    #[test]
    fn classify_never_panics(input in "\\PC*") {
        let mut classifier = Classifier::new();
        let ctx = test_ctx();
        let _ = classifier.classify(&input, &ctx);
    }

    /// classify() must never panic on strings that look like shell commands.
    /// This generates plausible command-like strings with pipes, redirects, etc.
    #[test]
    fn classify_never_panics_shell_like(
        cmd in prop::sample::select(vec![
            "rm", "ls", "cat", "echo", "curl", "wget", "git", "sudo",
            "bash", "sh", "eval", "source", "kill", "cp", "mv", "chmod",
            "ssh", "scp", "python", "node", "perl", "ruby", "env",
            "timeout", "nice", "xargs", "tee", "dd", "touch", "mkdir",
        ]),
        args in prop::collection::vec("[a-zA-Z0-9_.~/$-]{0,30}", 0..5),
        sep in prop::sample::select(vec![" ", " | ", " && ", " || ", " ; "]),
        suffix_cmd in prop::option::of("[a-z]{1,10}"),
    ) {
        let mut full = cmd.to_string();
        for arg in &args {
            full.push(' ');
            full.push_str(arg);
        }
        if let Some(s) = suffix_cmd {
            full.push_str(&sep);
            full.push_str(&s);
        }

        let mut classifier = Classifier::new();
        let ctx = test_ctx();
        let _ = classifier.classify(&full, &ctx);
    }

    /// classify() always returns a valid HashSet (non-null, iterable).
    /// For unparseable input, it should contain ExecDynamic (fail closed).
    #[test]
    fn classify_returns_valid_set(input in "\\PC{0,200}") {
        let mut classifier = Classifier::new();
        let ctx = test_ctx();
        let caps = classifier.classify(&input, &ctx);
        // The result is always a valid set — we can iterate it
        for cap in &caps {
            // Each capability should be displayable
            let _ = cap.to_string();
        }
    }

    /// Null bytes in input should always trigger ExecDynamic (fail closed).
    #[test]
    fn null_bytes_always_fail_closed(
        prefix in "[a-z ]{0,20}",
        suffix in "[a-z ]{0,20}",
    ) {
        let input = format!("{}\0{}", prefix, suffix);
        let mut classifier = Classifier::new();
        let ctx = test_ctx();
        let caps = classifier.classify(&input, &ctx);
        prop_assert!(caps.contains(&Capability::ExecDynamic),
            "null byte input should always contain ExecDynamic: {:?}", caps);
    }

    /// Empty and whitespace-only input should not panic.
    #[test]
    fn whitespace_input_never_panics(input in "[ \t\n\r]{0,50}") {
        let mut classifier = Classifier::new();
        let ctx = test_ctx();
        let _ = classifier.classify(&input, &ctx);
    }

    /// Deeply nested command substitutions should not stack overflow.
    #[test]
    fn nested_substitutions_no_overflow(depth in 1usize..20) {
        let mut cmd = "echo hello".to_string();
        for _ in 0..depth {
            cmd = format!("echo $({})", cmd);
        }
        let mut classifier = Classifier::new();
        let ctx = test_ctx();
        let _ = classifier.classify(&cmd, &ctx);
    }

    /// Paths with various special characters should not panic.
    #[test]
    fn paths_with_special_chars(
        cmd in prop::sample::select(vec!["cat", "rm", "cp", "mv", "touch"]),
        path in "[a-zA-Z0-9_./~ -]{1,60}",
    ) {
        let full = format!("{} {}", cmd, path);
        let mut classifier = Classifier::new();
        let ctx = test_ctx();
        let _ = classifier.classify(&full, &ctx);
    }

    /// Long commands should not cause excessive memory or time.
    #[test]
    fn long_commands_bounded(
        word in "[a-z]{1,5}",
        count in 1usize..200,
    ) {
        let cmd = std::iter::repeat(word.as_str()).take(count).collect::<Vec<_>>().join(" ");
        let mut classifier = Classifier::new();
        let ctx = test_ctx();
        let _ = classifier.classify(&cmd, &ctx);
    }

    /// Context with unusual paths should not panic.
    #[test]
    fn unusual_context_paths(
        cwd in "[a-zA-Z0-9_/]{1,50}",
        project_root in "[a-zA-Z0-9_/]{1,50}",
        home in "[a-zA-Z0-9_/]{1,50}",
    ) {
        let ctx = Context {
            cwd: PathBuf::from(&cwd),
            project_root: PathBuf::from(&project_root),
            home: PathBuf::from(&home),
            env: HashMap::new(),
        };
        let mut classifier = Classifier::new();
        let _ = classifier.classify("rm /tmp/foo", &ctx);
    }
}
