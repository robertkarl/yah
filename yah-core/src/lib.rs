pub mod capability;
pub mod commands;
pub mod context;
pub mod paths;
pub mod walker;
pub mod wrappers;

pub use capability::Capability;
pub use context::Context;

use std::collections::HashSet;
use tree_sitter::Parser;

/// The shell command capability classifier.
///
/// Holds a tree-sitter parser for reuse across multiple classify() calls
/// (useful in batch mode).
pub struct Classifier {
    parser: Parser,
}

impl Classifier {
    /// Create a new Classifier with a tree-sitter-bash parser.
    pub fn new() -> Self {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_bash::LANGUAGE.into())
            .expect("failed to load tree-sitter-bash grammar");
        Classifier { parser }
    }

    /// Classify a shell command string and return the set of capabilities it requires.
    ///
    /// This is a pure function: no filesystem access, no network, no side effects.
    /// Path normalization is string-level only. The caller (CLI) is responsible for
    /// resolving symlinks and populating canonicalized paths in Context.
    ///
    /// Returns {ExecDynamic} for unparseable input (fail closed).
    pub fn classify(&mut self, command: &str, ctx: &Context) -> HashSet<Capability> {
        // Reject null bytes
        if command.contains('\0') {
            let mut caps = HashSet::new();
            caps.insert(Capability::ExecDynamic);
            return caps;
        }

        let tree = match self.parser.parse(command, None) {
            Some(tree) => tree,
            None => {
                let mut caps = HashSet::new();
                caps.insert(Capability::ExecDynamic);
                return caps;
            }
        };

        let root = tree.root_node();

        // Check for parse errors at the root level
        if root.has_error() {
            // There are ERROR nodes somewhere in the tree.
            // We still walk the tree to extract what we can, but the presence of
            // errors means we also emit ExecDynamic.
            let mut caps = walker::walk_node(root, command, ctx);
            caps.insert(Capability::ExecDynamic);
            return caps;
        }

        walker::walk_node(root, command, ctx)
    }
}

impl Default for Classifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn test_ctx() -> Context {
        Context {
            cwd: PathBuf::from("/home/user/project"),
            project_root: PathBuf::from("/home/user/project"),
            home: PathBuf::from("/home/user"),
            env: HashMap::new(),
        }
    }

    #[test]
    fn safe_ls() {
        let mut c = Classifier::new();
        let caps = c.classify("ls", &test_ctx());
        assert!(caps.is_empty(), "ls should have no capabilities: {:?}", caps);
    }

    #[test]
    fn safe_echo() {
        let mut c = Classifier::new();
        let caps = c.classify("echo hello", &test_ctx());
        assert!(
            caps.is_empty(),
            "echo should have no capabilities: {:?}",
            caps
        );
    }

    #[test]
    fn safe_git_status() {
        let mut c = Classifier::new();
        let caps = c.classify("git status", &test_ctx());
        assert!(
            caps.is_empty(),
            "git status should have no capabilities: {:?}",
            caps
        );
    }

    #[test]
    fn curl_net_egress() {
        let mut c = Classifier::new();
        let caps = c.classify("curl https://example.com", &test_ctx());
        assert!(caps.contains(&Capability::NetEgress));
    }

    #[test]
    fn curl_pipe_bash() {
        let mut c = Classifier::new();
        let caps = c.classify("curl https://example.com/install.sh | bash", &test_ctx());
        assert!(caps.contains(&Capability::NetEgress));
        // bash without -c and without args is just a shell invocation, not exec-dynamic per se.
        // The pipeline itself is the danger. tree-sitter will parse `bash` as a command.
    }

    #[test]
    fn rm_inside_repo() {
        let mut c = Classifier::new();
        let caps = c.classify("rm foo.txt", &test_ctx());
        assert!(caps.contains(&Capability::DeleteInsideRepo));
    }

    #[test]
    fn rm_outside_repo() {
        let mut c = Classifier::new();
        let caps = c.classify("rm /etc/passwd", &test_ctx());
        assert!(caps.contains(&Capability::DeleteOutsideRepo));
    }

    #[test]
    fn sudo_rm() {
        let mut c = Classifier::new();
        let caps = c.classify("sudo rm /tmp/file", &test_ctx());
        assert!(caps.contains(&Capability::PrivilegeEscalation));
        assert!(caps.contains(&Capability::DeleteOutsideRepo));
    }

    #[test]
    fn eval_exec_dynamic() {
        let mut c = Classifier::new();
        let caps = c.classify("eval 'echo hello'", &test_ctx());
        assert!(caps.contains(&Capability::ExecDynamic));
    }

    #[test]
    fn git_force_push() {
        let mut c = Classifier::new();
        let caps = c.classify("git push --force origin main", &test_ctx());
        assert!(caps.contains(&Capability::HistoryRewrite));
        assert!(caps.contains(&Capability::NetEgress));
    }

    #[test]
    fn git_reset_hard() {
        let mut c = Classifier::new();
        let caps = c.classify("git reset --hard HEAD~1", &test_ctx());
        assert!(caps.contains(&Capability::HistoryRewrite));
    }

    #[test]
    fn kill_process() {
        let mut c = Classifier::new();
        let caps = c.classify("kill -9 1234", &test_ctx());
        assert!(caps.contains(&Capability::ProcessSignal));
    }

    #[test]
    fn read_ssh_key() {
        let mut c = Classifier::new();
        let caps = c.classify("cat ~/.ssh/id_rsa", &test_ctx());
        assert!(caps.contains(&Capability::ReadSecretPath));
    }

    #[test]
    fn write_redirect_outside() {
        let mut c = Classifier::new();
        let caps = c.classify("echo hello > /tmp/out.txt", &test_ctx());
        assert!(caps.contains(&Capability::WriteOutsideRepo));
    }

    #[test]
    fn write_redirect_inside() {
        let mut c = Classifier::new();
        let caps = c.classify("echo hello > ./output.txt", &test_ctx());
        assert!(caps.contains(&Capability::WriteInsideRepo));
    }

    #[test]
    fn python_http_server() {
        let mut c = Classifier::new();
        let caps = c.classify("python3 -m http.server", &test_ctx());
        assert!(caps.contains(&Capability::NetIngress));
    }

    #[test]
    fn compound_and() {
        let mut c = Classifier::new();
        let caps = c.classify("curl https://example.com && rm /tmp/file", &test_ctx());
        assert!(caps.contains(&Capability::NetEgress));
        assert!(caps.contains(&Capability::DeleteOutsideRepo));
    }

    #[test]
    fn null_byte_fail_closed() {
        let mut c = Classifier::new();
        let caps = c.classify("echo\0hello", &test_ctx());
        assert!(caps.contains(&Capability::ExecDynamic));
    }
}
