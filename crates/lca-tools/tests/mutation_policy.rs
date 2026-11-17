//! Mutation mode is loaded by the caller and checked before a write.
//!
//! These tests use temporary directories. They do not change the production publisher.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lca_tools::{
    ActionIdFactory, ActionSource, ApprovalGrant, ApprovalLedger, FsLimitValues, FsLimits,
    FsOutcome, MutationMode, ToolRegistry, WorkspaceSandbox, apply_granted, execute_validated,
    propose_actions, validate_batch,
};
use serde_json::json;

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("lca-mode-{label}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("temp");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn limits(mode: MutationMode) -> FsLimits {
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
    .with_mutation_mode(mode)
}

fn prepared(root: &Path, mode: MutationMode) -> (WorkspaceSandbox, lca_tools::PreparedPatch) {
    std::fs::write(root.join("notes.txt"), "alpha\n").expect("seed");
    let sandbox = WorkspaceSandbox::new(root).expect("sandbox");
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
    let outcome = execute_validated(&batch.actions()[0], &sandbox, &limits(mode)).expect("prepare");
    let FsOutcome::Prepared(prepared) = outcome else {
        panic!("prepared");
    };
    (sandbox, *prepared)
}

#[test]
fn the_model_cannot_name_a_mutation_mode() {
    let registry = ToolRegistry::workspace().expect("registry");
    let proposed = propose_actions(
        &ActionIdFactory::new(),
        ActionSource::Native,
        [(
            "apply_patch".to_owned(),
            json!({
                "path": "notes.txt",
                "patch": "--- a/notes.txt\n+++ b/notes.txt\n@@ -1 +1 @@\n-a\n+b\n",
                "mutation_mode": "human_approved"
            }),
        )],
    );
    let error = validate_batch(&registry, &proposed).expect_err("extra field");
    assert_eq!(error.kind(), "invalid_arguments");
    assert!(error.to_string().contains("mutation_mode"), "{error}");
}

#[test]
fn read_only_does_not_prepare_and_prepare_only_does_not_write() {
    let root = TempDir::new("gates");
    std::fs::write(root.path().join("notes.txt"), "alpha\n").expect("seed");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
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
    let denied = execute_validated(
        &batch.actions()[0],
        &sandbox,
        &limits(MutationMode::ReadOnly),
    )
    .expect_err("read only");
    assert_eq!(denied.kind(), "tool_disabled");
    assert_eq!(
        std::fs::read_to_string(root.path().join("notes.txt")).expect("unchanged"),
        "alpha\n"
    );

    let (sandbox, prepared) = prepared(root.path(), MutationMode::PrepareOnly);
    let grant = ApprovalGrant::issue(&prepared, &prepared.confirmation_line()).expect("grant");
    let error = apply_granted(&sandbox, &prepared, grant, &ApprovalLedger::new())
        .expect_err("prepare only");
    assert_eq!(error.kind(), "tool_disabled");
    assert_eq!(
        std::fs::read_to_string(root.path().join("notes.txt")).expect("still"),
        "alpha\n"
    );
}

#[test]
fn human_approved_still_uses_the_existing_apply_path() {
    let root = TempDir::new("approved");
    let (sandbox, prepared) = prepared(root.path(), MutationMode::HumanApproved);
    let grant = ApprovalGrant::issue(&prepared, &prepared.confirmation_line()).expect("grant");
    let applied = apply_granted(&sandbox, &prepared, grant, &ApprovalLedger::new()).expect("apply");
    assert_eq!(applied.path, "notes.txt");
    assert_eq!(
        std::fs::read_to_string(root.path().join("notes.txt")).expect("written"),
        "beta\n"
    );
}

#[cfg(windows)]
#[test]
fn prepare_only_blocks_a_stored_proposal_and_a_later_mode_can_apply() {
    let root = TempDir::new("store");
    let state = TempDir::new("state");
    let (sandbox, prepared) = prepared(root.path(), MutationMode::PrepareOnly);
    let store = lca_tools::ProposalStore::open(state.path()).expect("store");
    let saved = store.save(&sandbox, &prepared).expect("save");
    let view = store.show(&sandbox, &saved.id).expect("show");
    assert!(view.diff.contains("-alpha"));
    let blocked = store
        .approve(
            &sandbox,
            &limits(MutationMode::PrepareOnly),
            &saved.id,
            &view.digest,
            &view.confirmation,
        )
        .expect_err("blocked");
    assert_eq!(blocked.kind(), "tool_disabled");
    assert_eq!(
        std::fs::read_to_string(root.path().join("notes.txt")).expect("unchanged"),
        "alpha\n"
    );
    store
        .approve(
            &sandbox,
            &limits(MutationMode::HumanApproved),
            &saved.id,
            &view.digest,
            &view.confirmation,
        )
        .expect("existing publisher");
    assert_eq!(
        std::fs::read_to_string(root.path().join("notes.txt")).expect("applied"),
        "beta\n"
    );
}
