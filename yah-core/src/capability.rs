use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    NetEgress,
    NetIngress,
    WriteInsideRepo,
    WriteOutsideRepo,
    DeleteInsideRepo,
    DeleteOutsideRepo,
    ReadSecretPath,
    HistoryRewrite,
    ExecDynamic,
    ProcessSignal,
    PrivilegeEscalation,
    PackageInstall,
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Capability::NetEgress => "net-egress",
            Capability::NetIngress => "net-ingress",
            Capability::WriteInsideRepo => "write-inside-repo",
            Capability::WriteOutsideRepo => "write-outside-repo",
            Capability::DeleteInsideRepo => "delete-inside-repo",
            Capability::DeleteOutsideRepo => "delete-outside-repo",
            Capability::ReadSecretPath => "read-secret-path",
            Capability::HistoryRewrite => "history-rewrite",
            Capability::ExecDynamic => "exec-dynamic",
            Capability::ProcessSignal => "process-signal",
            Capability::PrivilegeEscalation => "privilege-escalation",
            Capability::PackageInstall => "package-install",
        };
        write!(f, "{}", s)
    }
}

impl Capability {
    pub fn from_str_name(s: &str) -> Option<Capability> {
        match s {
            "net-egress" => Some(Capability::NetEgress),
            "net-ingress" => Some(Capability::NetIngress),
            "write-inside-repo" => Some(Capability::WriteInsideRepo),
            "write-outside-repo" => Some(Capability::WriteOutsideRepo),
            "delete-inside-repo" => Some(Capability::DeleteInsideRepo),
            "delete-outside-repo" => Some(Capability::DeleteOutsideRepo),
            "read-secret-path" => Some(Capability::ReadSecretPath),
            "history-rewrite" => Some(Capability::HistoryRewrite),
            "exec-dynamic" => Some(Capability::ExecDynamic),
            "process-signal" => Some(Capability::ProcessSignal),
            "privilege-escalation" => Some(Capability::PrivilegeEscalation),
            "package-install" => Some(Capability::PackageInstall),
            _ => None,
        }
    }
}
