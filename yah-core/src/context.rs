use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Context {
    /// Current working directory (canonicalized absolute path).
    pub cwd: PathBuf,
    /// Project root directory (canonicalized absolute path).
    pub project_root: PathBuf,
    /// User home directory.
    pub home: PathBuf,
    /// Environment variables for resolving $VAR where statically possible.
    pub env: HashMap<String, String>,
}
