//! CLI boundary for restoration. The binary does not accept a piped approval.

#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use lca_tools::{
    ActionIdFactory, ActionSource, ApplyFault, FsLimitValues, FsLimits, FsOutcome, ProposalStore,
    ToolRegistry, WorkspaceSandbox, execute_validated, propose_actions, validate_batch,
};
use serde_json::json;

#[test]
fn restoration_approve_rejects_flags_and_a_piped_line() {
    for flag in ["--yes", "--force", "--auto-approve"] {
        let output = Command::new(env!("CARGO_BIN_EXE_lca"))
            .args([
                "patch",
                "restoration",
                "approve",
                flag,
                "00000000-0000-0000-0000-000000000001",
            ])
            .output()
            .expect("run");
        assert_ne!(output.status.code(), Some(0), "{flag}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("restored: true"), "{stderr}");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_lca"))
        .args([
            "patch",
            "restoration",
            "approve",
            "00000000-0000-0000-0000-000000000001",
        ])
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_ne!(output.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("interactive"), "{stderr}");
}

#[test]
fn live_restoration_stops_before_human_approval() {
    let root = temp_dir("live-ws");
    let state = temp_dir("live-store");
    fs::write(root.join("notes.txt"), b"alpha\n").expect("seed");
    let sandbox = WorkspaceSandbox::new(&root).expect("sandbox");
    let store = ProposalStore::open(&state).expect("store");
    let prepared = prepare(&sandbox);
    let saved = store.save(&sandbox, &prepared).expect("save");
    let view = store.show(&sandbox, &saved.id).expect("show");
    let fault = store.approve_with(
        &sandbox,
        &limits(),
        &saved.id,
        &view.digest,
        &view.confirmation,
        ApplyFault::DuringPublish,
    );
    assert!(fault.is_err());
    let torn = fs::read(root.join("notes.txt")).expect("torn");
    assert_ne!(torn, b"alpha\n");
    assert_ne!(torn, b"beta\n");
    let _ = store.recover(&sandbox, &saved.id);
    let config = root.join("lca.toml");
    let body = format!(
        "workspace_root = '{}'\n[ollama]\nendpoint = 'http://127.0.0.1:9'\nmodel = 'lca-30b-agent'\nrequest_timeout_secs = 1\n",
        root.display().to_string().replace('\\', "/")
    );
    fs::write(&config, body).expect("config");
    let config_arg = config.to_str().expect("utf-8");
    let inspect = lca(config_arg, &state, &["patch", "inspect", &saved.id]);
    let inspect_out = String::from_utf8_lossy(&inspect.stdout);
    assert_eq!(
        inspect.status.code(),
        Some(0),
        "{inspect_out}\n{}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    assert!(inspect_out.contains("matches_neither"), "{inspect_out}");
    assert!(inspect_out.contains("pinned_in_place"), "{inspect_out}");
    let prepare_out = lca(
        config_arg,
        &state,
        &["patch", "restoration", "prepare", &saved.id],
    );
    let stdout = String::from_utf8_lossy(&prepare_out.stdout);
    assert_eq!(
        prepare_out.status.code(),
        Some(0),
        "{stdout}\n{}",
        String::from_utf8_lossy(&prepare_out.stderr)
    );
    let restoration_id = field(&stdout, "restoration_id");
    let shown = lca(
        config_arg,
        &state,
        &["patch", "restoration", "show", &restoration_id],
    );
    let shown_out = String::from_utf8_lossy(&shown.stdout);
    assert_eq!(shown.status.code(), Some(0), "{shown_out}");
    assert!(
        shown_out.contains("source: sealed-publication-evidence"),
        "{shown_out}"
    );
    assert!(shown_out.contains("confirmation: restore "), "{shown_out}");
    assert!(shown_out.contains("+alpha"), "{shown_out}");
    assert!(!shown_out.contains("confirmation: approve "), "{shown_out}");
    let approve = lca(
        config_arg,
        &state,
        &["patch", "restoration", "approve", &restoration_id],
    );
    let approve_err = String::from_utf8_lossy(&approve.stderr);
    assert_ne!(approve.status.code(), Some(0), "{approve_err}");
    assert!(approve_err.contains("interactive"), "{approve_err}");
    assert_eq!(fs::read(root.join("notes.txt")).expect("untouched"), torn);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&state);
}

fn lca(config: &str, state: &Path, args: &[&str]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_lca"));
    command.arg("--config").arg(config);
    command.args(args);
    command.env("LCA_STATE_DIR", state);
    command.output().expect("lca")
}

fn field(text: &str, key: &str) -> String {
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}: ")))
        .expect(key)
        .to_owned()
}

fn prepare(sandbox: &WorkspaceSandbox) -> lca_tools::PreparedPatch {
    let patch = "--- a/notes.txt\n+++ b/notes.txt\n@@ -1,1 +1,1 @@\n-alpha\n+beta\n";
    let registry = ToolRegistry::workspace().expect("registry");
    let proposed = propose_actions(
        &ActionIdFactory::new(),
        ActionSource::Native,
        [(
            "apply_patch".to_owned(),
            json!({"path": "notes.txt", "patch": patch}),
        )],
    );
    let batch = validate_batch(&registry, &proposed).expect("batch");
    let outcome = execute_validated(&batch.actions()[0], sandbox, &limits()).expect("prepare");
    let FsOutcome::Prepared(prepared) = outcome else {
        panic!("prepared");
    };
    *prepared
}

fn limits() -> FsLimits {
    FsLimits::try_new(FsLimitValues {
        read_enabled: true,
        write_enabled: true,
        max_file_size_bytes: 1024 * 1024,
        max_response_bytes: 256 * 1024,
        max_directory_entries: 100,
        max_search_matches: 20,
        max_search_files: 100,
        max_search_total_bytes: 1024 * 1024,
    })
    .expect("limits")
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path =
        std::env::temp_dir().join(format!("lca-live-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).expect("temp");
    path
}
