use crate::context::Context;
use std::path::{Component, PathBuf};

/// Sensitive path patterns. Checked against normalized absolute paths.
const SENSITIVE_PREFIXES: &[&str] = &[
    "/.ssh/",
    "/.aws/",
    "/.gnupg/",
    "/.config/gcloud/",
    "/.config/gh/",
    "/.kube/",
    "/.password-store/",
    "/.local/share/keyrings/",
];

const SENSITIVE_EXACT_SUFFIXES: &[&str] = &[
    "/.docker/config.json",
    "/.netrc",
    "/.npmrc",
    "/.pypirc",
    "/.gem/credentials",
    "/.vault-token",
];

const SENSITIVE_FILENAMES: &[&str] = &[".env", "credentials.json"];

const SENSITIVE_FILENAME_PREFIXES: &[&str] = &[".env.", "service-account"];

/// Normalize a path string to an absolute PathBuf using string-level operations only.
/// No filesystem access.
///
/// - Expands `~` to `ctx.home`
/// - Expands `$HOME` and `${HOME}` to `ctx.home`
/// - Resolves other `$VAR` / `${VAR}` from `ctx.env` (simple forms only)
/// - Resolves relative paths against `ctx.cwd`
/// - Collapses `.` and `..` segments
///
/// Returns None if the path contains an unresolvable variable expansion.
pub fn normalize_path(raw: &str, ctx: &Context) -> Option<PathBuf> {
    let expanded = expand_vars(raw, ctx)?;

    let path = if expanded.starts_with('/') {
        PathBuf::from(&expanded)
    } else {
        ctx.cwd.join(&expanded)
    };

    Some(collapse_dots(&path))
}

/// Expand ~ and $VAR in a path string. Returns None if a variable can't be resolved.
fn expand_vars(raw: &str, ctx: &Context) -> Option<String> {
    let mut result = String::with_capacity(raw.len());
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '~' && (i == 0) && (i + 1 >= chars.len() || chars[i + 1] == '/') {
            result.push_str(ctx.home.to_str().unwrap_or("/"));
            i += 1;
        } else if chars[i] == '$' {
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
            if braced {
                // Must find closing brace, and no special operators
                if i >= chars.len() || chars[i] != '}' {
                    return None;
                }
                let var_name: String = chars[start..i].iter().collect();
                i += 1; // skip '}'

                // Check for parameter expansion operators — fail closed
                if var_name.contains(':') || var_name.contains('#') || var_name.contains('%') {
                    return None;
                }
                let value = resolve_var(&var_name, ctx)?;
                result.push_str(&value);
            } else {
                let var_name: String = chars[start..i].iter().collect();
                if var_name.is_empty() {
                    return None;
                }
                let value = resolve_var(&var_name, ctx)?;
                result.push_str(&value);
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    Some(result)
}

fn resolve_var(name: &str, ctx: &Context) -> Option<String> {
    if name == "HOME" {
        return Some(ctx.home.to_str().unwrap_or("/").to_string());
    }
    ctx.env.get(name).cloned()
}

/// Collapse `.` and `..` components without filesystem access.
fn collapse_dots(path: &PathBuf) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {} // skip `.`
            Component::ParentDir => {
                // Pop the last normal component if any
                if let Some(Component::Normal(_)) = components.last() {
                    components.pop();
                } else {
                    components.push(component);
                }
            }
            _ => components.push(component),
        }
    }
    components.iter().collect()
}

/// Check if a normalized absolute path is inside project_root.
pub fn is_inside_repo(path: &PathBuf, ctx: &Context) -> bool {
    path_starts_with(path, &ctx.project_root)
}

/// Platform-aware path prefix check.
fn path_starts_with(path: &PathBuf, prefix: &PathBuf) -> bool {
    let path_str = path.to_str().unwrap_or("");
    let prefix_str = prefix.to_str().unwrap_or("");

    if cfg!(target_os = "macos") {
        // Case-insensitive comparison on macOS
        let p = path_str.to_lowercase();
        let r = prefix_str.to_lowercase();
        p.starts_with(&r) && (p.len() == r.len() || p.as_bytes().get(r.len()) == Some(&b'/'))
    } else {
        path.starts_with(prefix)
    }
}

/// Check if a path refers to a sensitive location (secrets, credentials).
pub fn is_sensitive_path(path: &PathBuf, ctx: &Context) -> bool {
    let path_str = path.to_str().unwrap_or("");
    let home_str = ctx.home.to_str().unwrap_or("");

    // Check home-relative sensitive prefixes: ~/.ssh/ etc.
    for prefix in SENSITIVE_PREFIXES {
        let full_prefix = format!("{}{}", home_str, prefix);
        if path_str_starts_with(path_str, &full_prefix) {
            return true;
        }
    }

    // Check home-relative exact suffixes: ~/.netrc etc.
    for suffix in SENSITIVE_EXACT_SUFFIXES {
        let full_path = format!("{}{}", home_str, suffix);
        if path_str_eq(path_str, &full_path) {
            return true;
        }
    }

    // Check sensitive filenames anywhere in the path
    if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
        for sensitive in SENSITIVE_FILENAMES {
            if filename_eq(filename, sensitive) {
                return true;
            }
        }
        for prefix in SENSITIVE_FILENAME_PREFIXES {
            if filename_starts_with(filename, prefix) {
                return true;
            }
        }
    }

    false
}

fn path_str_starts_with(path: &str, prefix: &str) -> bool {
    if cfg!(target_os = "macos") {
        path.to_lowercase().starts_with(&prefix.to_lowercase())
    } else {
        path.starts_with(prefix)
    }
}

fn path_str_eq(a: &str, b: &str) -> bool {
    if cfg!(target_os = "macos") {
        a.to_lowercase() == b.to_lowercase()
    } else {
        a == b
    }
}

fn filename_eq(a: &str, b: &str) -> bool {
    if cfg!(target_os = "macos") {
        a.to_lowercase() == b.to_lowercase()
    } else {
        a == b
    }
}

fn filename_starts_with(filename: &str, prefix: &str) -> bool {
    if cfg!(target_os = "macos") {
        filename.to_lowercase().starts_with(&prefix.to_lowercase())
    } else {
        filename.starts_with(prefix)
    }
}

/// Check if a path is in a scratch directory (/tmp, /var/tmp, $TMPDIR).
/// Writes and deletes here are treated like inside-repo (allowed by default).
pub fn is_scratch_path(path: &PathBuf) -> bool {
    let path_str = path.to_str().unwrap_or("");
    path_str.starts_with("/tmp/")
        || path_str == "/tmp"
        || path_str.starts_with("/var/tmp/")
        || path_str == "/var/tmp"
        || path_str.starts_with("/private/tmp/")
        || path_str == "/private/tmp"
}

/// Check if a path is a safe /dev device — reads/writes to these are ignored.
/// Only true sinks/sources with no side effects.
pub fn is_dev_null(path: &PathBuf) -> bool {
    matches!(
        path.to_str(),
        Some("/dev/null") | Some("/dev/zero") | Some("/dev/urandom") | Some("/dev/random")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_ctx() -> Context {
        Context {
            cwd: PathBuf::from("/home/user/project"),
            project_root: PathBuf::from("/home/user/project"),
            home: PathBuf::from("/home/user"),
            env: HashMap::new(),
        }
    }

    #[test]
    fn normalize_absolute() {
        let ctx = test_ctx();
        assert_eq!(
            normalize_path("/etc/passwd", &ctx),
            Some(PathBuf::from("/etc/passwd"))
        );
    }

    #[test]
    fn normalize_relative() {
        let ctx = test_ctx();
        assert_eq!(
            normalize_path("foo.txt", &ctx),
            Some(PathBuf::from("/home/user/project/foo.txt"))
        );
    }

    #[test]
    fn normalize_tilde() {
        let ctx = test_ctx();
        assert_eq!(
            normalize_path("~/.ssh/id_rsa", &ctx),
            Some(PathBuf::from("/home/user/.ssh/id_rsa"))
        );
    }

    #[test]
    fn normalize_dotdot() {
        let ctx = test_ctx();
        assert_eq!(
            normalize_path("../other/file", &ctx),
            Some(PathBuf::from("/home/user/other/file"))
        );
    }

    #[test]
    fn normalize_home_var() {
        let ctx = test_ctx();
        assert_eq!(
            normalize_path("$HOME/.aws/credentials", &ctx),
            Some(PathBuf::from("/home/user/.aws/credentials"))
        );
    }

    #[test]
    fn inside_repo() {
        let ctx = test_ctx();
        assert!(is_inside_repo(
            &PathBuf::from("/home/user/project/src/main.rs"),
            &ctx
        ));
    }

    #[test]
    fn outside_repo() {
        let ctx = test_ctx();
        assert!(!is_inside_repo(&PathBuf::from("/etc/passwd"), &ctx));
    }

    #[test]
    fn sensitive_ssh() {
        let ctx = test_ctx();
        assert!(is_sensitive_path(
            &PathBuf::from("/home/user/.ssh/id_rsa"),
            &ctx
        ));
    }

    #[test]
    fn sensitive_env() {
        let ctx = test_ctx();
        assert!(is_sensitive_path(
            &PathBuf::from("/home/user/project/.env"),
            &ctx
        ));
    }

    #[test]
    fn not_sensitive() {
        let ctx = test_ctx();
        assert!(!is_sensitive_path(
            &PathBuf::from("/home/user/project/src/main.rs"),
            &ctx
        ));
    }
}
