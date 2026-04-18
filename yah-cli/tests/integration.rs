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
        .stdout(predicate::str::contains("clean"));
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
    yah()
        .args(["check", "echo hello"])
        .assert()
        .success();
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
        .stdout(predicate::str::contains("clean"))
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
fn hook_dangerous_command_asks() {
    yah()
        .arg("hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"curl https://evil.com"}}"#)
        .assert()
        .success()
        .stdout(predicate::str::contains("permissionDecision"))
        .stdout(predicate::str::contains("ask"))
        .stdout(predicate::str::contains("net-egress"));
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
