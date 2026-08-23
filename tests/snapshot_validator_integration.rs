use rove::addrbook::BookBuilder;
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/snapshot_v4")
        .join(name)
}

fn run_file(node_id: &str, path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rove"))
        .arg("validate-snapshot")
        .arg("--node-id")
        .arg(node_id)
        .arg(path)
        .output()
        .expect("run snapshot validator")
}

fn run_stdin(node_id: &str, bytes: &[u8], extra_args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rove"));
    command
        .arg("validate-snapshot")
        .arg("--node-id")
        .arg(node_id)
        .args(extra_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn snapshot validator");
    child
        .stdin
        .take()
        .expect("validator stdin")
        .write_all(bytes)
        .expect("write snapshot stdin");
    child.wait_with_output().expect("wait for validator")
}

fn json_output(output: &Output) -> Value {
    assert!(
        output.stderr.is_empty(),
        "expected no stderr, got {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout.clone()).expect("stdout is utf-8");
    assert_eq!(
        text.lines().count(),
        1,
        "validator must emit exactly one JSON line: {text:?}"
    );
    serde_json::from_str(text.trim()).expect("stdout is one JSON object")
}

fn temp_path(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rove-snapshot-validator-{}-{nonce}-{name}",
        std::process::id()
    ))
}

#[test]
fn validates_v4_file_with_machine_readable_secret_safe_summary() {
    let output = run_file("edge-1", &fixture("policies.json"));
    assert!(output.status.success());
    let json = json_output(&output);
    assert_eq!(json["ok"], true);
    assert_eq!(json["schema_version"], 4);
    assert_eq!(json["version"], 41);
    assert_eq!(json["users"], 3);
    assert_eq!(json["routing_policies"], 3);
    assert_eq!(json["egresses"], 3);
    let text = String::from_utf8_lossy(&output.stdout);
    for secret in [
        "alice-login-secret",
        "alice-tuic-secret",
        "pw-a-secret",
        "pw-a-edge1-secret",
    ] {
        assert!(!text.contains(secret), "validator leaked {secret:?}");
    }
}

#[test]
fn validates_snapshot_from_default_stdin_input() {
    let bytes = std::fs::read(fixture("policies.json")).unwrap();
    let output = run_stdin("edge-0", &bytes, &[]);
    assert!(output.status.success());
    let json = json_output(&output);
    assert_eq!(json["ok"], true);
    assert_eq!(json["schema_version"], 4);
}

#[test]
fn loads_optional_addrbook_and_runs_real_compile_path() {
    let mut builder = BookBuilder::new(1);
    builder.add_rule("blocked", "bad.example").unwrap();
    builder.add_rule("viaproxy", "proxy.example").unwrap();
    let book_path = temp_path("book.rab");
    std::fs::write(&book_path, builder.build_bytes().unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_rove"))
        .arg("validate-snapshot")
        .arg("--node-id")
        .arg("edge-0")
        .arg("--addrbook")
        .arg(&book_path)
        .arg(fixture("book_policy.json"))
        .output()
        .expect("run validator with addrbook");
    let _ = std::fs::remove_file(book_path);

    assert!(output.status.success());
    let json = json_output(&output);
    assert_eq!(json["ok"], true);
}

#[test]
fn node_id_selects_and_validates_the_matching_override() {
    let path = fixture("invalid/node_override_new_egress.json");
    let other_node = run_file("edge-0", &path);
    assert!(other_node.status.success());
    assert_eq!(json_output(&other_node)["ok"], true);

    let matching_node = run_file("edge-1", &path);
    assert!(!matching_node.status.success());
    let json = json_output(&matching_node);
    assert_eq!(json["ok"], false);
    assert_eq!(json["stage"], "compile");
}

#[test]
fn malformed_json_and_missing_references_are_machine_failures_without_secrets() {
    let malformed = run_stdin("edge-0", br#"{"schema_version":4,"#, &[]);
    assert!(!malformed.status.success());
    let malformed_json = json_output(&malformed);
    assert_eq!(malformed_json["ok"], false);
    assert_eq!(malformed_json["stage"], "decode");

    let secret = "validator-user-secret";
    let missing_ref = format!(
        r#"{{
          "schema_version":4,
          "version":1,
          "users":{{"alice":{{"password":"{secret}","policy":"p"}}}},
          "routing_policies":{{"p":{{"routes":[{{
            "selectors":["example.com"],
            "action":{{"type":"egress","egress":"missing"}}
          }}]}}}},
          "egresses":{{}}
        }}"#
    );
    let failed = run_stdin("edge-0", missing_ref.as_bytes(), &[]);
    assert!(!failed.status.success());
    let failed_json = json_output(&failed);
    assert_eq!(failed_json["ok"], false);
    assert_eq!(failed_json["stage"], "compile");
    assert!(!String::from_utf8_lossy(&failed.stdout).contains(secret));
}

#[test]
fn bad_arguments_and_read_errors_use_the_json_contract() {
    let missing_node = Command::new(env!("CARGO_BIN_EXE_rove"))
        .arg("validate-snapshot")
        .arg(fixture("policies.json"))
        .output()
        .expect("run validator without node id");
    assert!(!missing_node.status.success());
    let json = json_output(&missing_node);
    assert_eq!(json["stage"], "arguments");

    let missing_file = run_file("edge-0", Path::new("/definitely/not/a/snapshot.json"));
    assert!(!missing_file.status.success());
    let json = json_output(&missing_file);
    assert_eq!(json["stage"], "read");
}
