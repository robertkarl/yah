use assert_cmd::Command;
use predicates::prelude::*;

fn yah() -> Command {
    Command::cargo_bin("yah").unwrap()
}

#[test]
fn classify_safe_command() {
    yah()
        .args(["classify", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains("CLEAN"));
}

#[test]
fn classify_curl() {
    yah()
        .args(["classify", "curl https://example.com"])
        .assert()
        .success()
        .stdout(predicate::str::contains("net-egress"));
}

#[test]
fn classify_json() {
    yah()
        .args(["classify", "--json", "curl https://example.com"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"net-egress\""));
}

#[test]
fn check_safe_exits_0() {
    yah().args(["check", "echo hello"]).assert().success();
}

#[test]
fn check_dangerous_exits_1() {
    yah()
        .args(["check", "curl https://example.com"])
        .assert()
        .code(1);
}

#[test]
fn explain_shows_capabilities() {
    yah()
        .args(["explain", "sudo rm -rf /"])
        .assert()
        .success()
        .stdout(predicate::str::contains("privilege-escalation"))
        .stdout(predicate::str::contains("delete-outside-repo"));
}

#[test]
fn classify_stdin() {
    yah()
        .arg("classify")
        .write_stdin("ls\ncurl example.com\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("CLEAN"))
        .stdout(predicate::str::contains("net-egress"));
}

#[test]
fn classify_quiet_safe() {
    yah()
        .args(["classify", "--quiet", "ls"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn check_quiet_dangerous() {
    yah()
        .args(["check", "--quiet", "curl example.com"])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty());
}

#[test]
fn hook_safe_command_no_output() {
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn hook_allowed_capability_no_output() {
    // net-egress is in the allow policy — should pass silently
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"curl https://example.com"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn hook_ask_capability_prompts() {
    // delete-outside-repo triggers ask
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"rm /opt/foo"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("ask"))
        .stdout(predicate::str::contains(
            "Needs approval: [delete-outside-repo]",
        ));
}

#[test]
fn hook_deny_history_rewrite_with_net_egress() {
    // history-rewrite + net-egress is denied by combination policy
    yah()
        .arg("hook")
        .write_stdin(
            r#"{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}"#,
        )
        .assert()
        .success()
        .stdout(predicate::str::contains("deny"))
        .stdout(predicate::str::contains("yah blocked this command"))
        .stdout(predicate::str::contains(
            "Denied by policy: [history-rewrite + net-egress]",
        ));
}

#[test]
fn hook_ask_history_rewrite_without_net_egress() {
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"git commit --amend"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("ask"))
        .stdout(predicate::str::contains(
            "Needs approval: [history-rewrite]",
        ));
}

#[test]
fn hook_ask_dynamic_git_push_flags() {
    yah()
        .arg("hook")
        .write_stdin(
            r#"{"tool_name":"Bash","tool_input":{"command":"FLAGS=--force && git push $FLAGS"}}"#,
        )
        .assert()
        .success()
        .stdout(predicate::str::contains("ask"))
        .stdout(predicate::str::contains("exec-dynamic"));
}

#[test]
fn hook_non_bash_tool_allows() {
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Edit","tool_input":{"file_path":"/etc/passwd"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn hook_invalid_json_allows() {
    yah()
        .arg("hook")
        .write_stdin("not json")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn hook_deny_global_pip_install() {
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"pip install requests"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("deny"))
        .stdout(predicate::str::contains("blocked global pip install"));
}

#[test]
fn hook_deny_global_pip3_install() {
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"pip3 install flask"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("deny"))
        .stdout(predicate::str::contains("blocked global pip install"));
}

#[test]
fn hook_deny_python_module_pip_install() {
    yah()
        .arg("hook")
        .write_stdin(
            r#"{"tool_name":"Bash","tool_input":{"command":"python -m pip install requests"}}"#,
        )
        .assert()
        .success()
        .stdout(predicate::str::contains("deny"))
        .stdout(predicate::str::contains("blocked global pip install"));
}

#[test]
fn hook_deny_npm_global_install() {
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"npm install -g typescript"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("deny"))
        .stdout(predicate::str::contains("blocked global npm install"));
}

#[test]
fn hook_ask_brew_install() {
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"brew install jq"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("ask"))
        .stdout(predicate::str::contains("package-install"));
}

#[test]
fn hook_allow_pip_install_target() {
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"pip install --target ./deps requests"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn hook_allow_pip_editable_install() {
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"pip install -e ."}}"#)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn hook_ask_ssh_sensitive_host() {
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"ssh 192.168.50.57"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("ask"))
        .stdout(predicate::str::contains("sensitive host"));
}

#[test]
fn hook_ask_ssh_user_at_sensitive_host() {
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"ssh root@192.168.50.57"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("ask"))
        .stdout(predicate::str::contains("sensitive host"));
}

#[test]
fn hook_ask_wrapped_ssh_sensitive_host() {
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"env SSH_AUTH_SOCK=/tmp/socket ssh root@192.168.50.57"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("ask"))
        .stdout(predicate::str::contains("sensitive host"));
}

#[test]
fn hook_allow_ssh_other_host() {
    // SSH to a non-sensitive host should allow (net-egress is in allow policy)
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"ssh user@example.com"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}
