//! Cross-process approval. The second process is a real console, not a pipe.
//!
//! These tests use a temporary workspace. They do not modify the developer tree.

#![cfg(windows)]

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use lca_platform::spawn_console;
use lca_tools::{
    ActionIdFactory, ActionSource, FsLimitValues, FsLimits, FsOutcome, ProposalStore, ToolRegistry,
    WorkspaceSandbox, execute_validated, propose_actions, validate_batch,
};
use serde_json::json;

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("lca-approve-{label}-{nanos}"));
        fs::create_dir_all(&path).expect("temp");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn limits() -> FsLimits {
    FsLimits::try_new(FsLimitValues {
        read_enabled: true,
        write_enabled: true,
        max_file_size_bytes: 1_048_576,
        max_response_bytes: 262_144,
        max_directory_entries: 100,
        max_search_matches: 100,
        max_search_files: 100,
        max_search_total_bytes: 1_048_576,
    })
    .expect("limits")
}

fn prepare_and_save(root: &Path, old: &str, new: &str) -> String {
    let sandbox = WorkspaceSandbox::new(root).expect("sandbox");
    let patch = format!("--- a/notes.txt\n+++ b/notes.txt\n@@ -1,1 +1,1 @@\n-{old}\n+{new}\n");
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
    let outcome = execute_validated(&batch.actions()[0], &sandbox, &limits()).expect("prepare");
    let FsOutcome::Prepared(prepared) = outcome else {
        panic!("prepared");
    };
    let store = ProposalStore::user_local().expect("store");
    store.save(&sandbox, &prepared).expect("save").id
}

fn config_for(root: &Path) -> PathBuf {
    let config = root.join("lca.toml");
    let body = format!(
        "workspace_root = '{}'\n",
        root.display().to_string().replace('\\', "/")
    );
    fs::write(&config, body).expect("config");
    config
}

fn lca(args: &[OsString]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lca"))
        .args(args)
        .output()
        .expect("lca")
}

fn field(text: &str, key: &str) -> String {
    let prefix = format!("{key}: ");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
        .unwrap_or_default()
}

fn proposal_path(id: &str) -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA");
    let root = PathBuf::from(base).join("lca").join("proposals");
    let mut found = None;
    if let Ok(workspaces) = fs::read_dir(&root) {
        for workspace in workspaces.flatten() {
            let candidate = workspace.path().join(format!("{id}.lcap"));
            if candidate.is_file() {
                found = Some(candidate);
                break;
            }
        }
    }
    found.expect("proposal file")
}

#[test]
fn a_second_process_can_show_and_approve_only_the_reviewed_bytes() {
    let workspace = TempDir::new("cross");
    fs::write(workspace.path().join("notes.txt"), "alpha\n").expect("notes");
    let config = config_for(workspace.path());
    let id = prepare_and_save(workspace.path(), "alpha", "beta");
    assert_eq!(
        fs::read_to_string(workspace.path().join("notes.txt")).expect("unchanged"),
        "alpha\n"
    );

    let shown = lca(&[
        OsString::from("patch"),
        OsString::from("show"),
        OsString::from(&id),
        OsString::from("--config"),
        OsString::from(config.as_os_str()),
    ]);
    let stdout = String::from_utf8_lossy(&shown.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&shown.stderr).into_owned();
    assert_eq!(shown.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("path: notes.txt\n"), "{stdout}");
    assert!(stdout.contains("-alpha"), "{stdout}");
    assert!(stdout.contains("+beta"), "{stdout}");
    assert_eq!(field(&stdout, "target_status"), "matches_original");
    let confirmation = field(&stdout, "confirmation");
    assert!(
        confirmation.starts_with(&format!("approve {id} ")),
        "{confirmation}"
    );
    assert_eq!(field(&stdout, "digest").len(), 64);

    let program = PathBuf::from(env!("CARGO_BIN_EXE_lca"));
    let approved = spawn_console(
        &program,
        &[
            OsString::from("patch"),
            OsString::from("approve"),
            OsString::from(&id),
            OsString::from("--config"),
            OsString::from(config.as_os_str()),
        ],
        &format!("{confirmation}\r\n"),
    )
    .expect("console");
    let transcript = String::from_utf8_lossy(&approved.output);
    assert_eq!(approved.exit_code, 0, "{transcript}");
    assert!(transcript.contains("applied: true"), "{transcript}");
    assert_eq!(
        fs::read_to_string(workspace.path().join("notes.txt")).expect("applied"),
        "beta\n"
    );

    let again = spawn_console(
        &program,
        &[
            OsString::from("patch"),
            OsString::from("approve"),
            OsString::from(&id),
            OsString::from("--config"),
            OsString::from(config.as_os_str()),
        ],
        &format!("{confirmation}\r\n"),
    )
    .expect("second console");
    assert_ne!(
        again.exit_code,
        0,
        "{}",
        String::from_utf8_lossy(&again.output)
    );
    assert_eq!(
        fs::read_to_string(workspace.path().join("notes.txt")).expect("once"),
        "beta\n"
    );

    let path = proposal_path(&id);
    let mut bytes = fs::read(&path).expect("ciphertext");
    let last = bytes.len() - 1;
    bytes[last] ^= 0x5a;
    fs::write(&path, &bytes).expect("tamper");
    let tampered = lca(&[
        OsString::from("patch"),
        OsString::from("show"),
        OsString::from(&id),
        OsString::from("--config"),
        OsString::from(config.as_os_str()),
    ]);
    assert_ne!(tampered.status.code(), Some(0));
    let tampered_err = String::from_utf8_lossy(&tampered.stderr);
    assert!(
        tampered_err.contains("proposal") || tampered_err.contains("protection"),
        "{tampered_err}"
    );

    fs::write(workspace.path().join("notes.txt"), "beta\n").expect("restore");
    let next_id = prepare_and_save(workspace.path(), "beta", "gamma");
    fs::write(workspace.path().join("notes.txt"), "other\n").expect("change");
    let review = lca(&[
        OsString::from("patch"),
        OsString::from("show"),
        OsString::from(&next_id),
        OsString::from("--config"),
        OsString::from(config.as_os_str()),
    ]);
    let review_out = String::from_utf8_lossy(&review.stdout).into_owned();
    assert_eq!(review.status.code(), Some(0), "{review_out}");
    assert_eq!(field(&review_out, "target_status"), "changed");
    let line = field(&review_out, "confirmation");
    let refused = spawn_console(
        &program,
        &[
            OsString::from("patch"),
            OsString::from("approve"),
            OsString::from(&next_id),
            OsString::from("--config"),
            OsString::from(config.as_os_str()),
        ],
        &format!("{line}\r\n"),
    )
    .expect("changed console");
    assert_ne!(
        refused.exit_code,
        0,
        "{}",
        String::from_utf8_lossy(&refused.output)
    );
    assert_eq!(
        fs::read_to_string(workspace.path().join("notes.txt")).expect("kept"),
        "other\n"
    );
}
