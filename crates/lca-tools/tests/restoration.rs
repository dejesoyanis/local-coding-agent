//! Restoration contract, evidence, and verified-restore tests.
//!
//! Destructive cases use a temporary workspace. Approval lines are the restoration
//! confirmation, never the proposal confirmation.

#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lca_tools::{
    ActionIdFactory, ActionSource, ApplyFault, FsLimitValues, FsLimits, FsOutcome, ProposalStore,
    ToolRegistry, WorkspaceSandbox, execute_validated, propose_actions, validate_batch,
};
use serde_json::json;

#[test]
fn a_torn_file_is_restored_once_and_the_old_approval_is_rejected() {
    let fx = torn("restore-once");
    let evidence_before = evidence_bytes(&fx.state);
    let prepared = fx
        .store
        .prepare_restoration(&fx.sandbox, &fx.proposal_id)
        .expect("prepare");
    let blocked = fx.store.prepare_restoration(&fx.sandbox, &fx.proposal_id);
    assert_eq!(blocked.expect_err("open").kind(), "restoration_rejected");
    let view = fx
        .store
        .show_restoration(&fx.sandbox, &prepared.id)
        .expect("show");
    assert_eq!(view.summary.state, "prepared");
    assert_eq!(view.source, "sealed-publication-evidence");
    assert_eq!(view.target_status, "matches_bound");
    assert!(view.confirmation.starts_with("restore "));
    assert!(view.confirmation.contains(&prepared.id));
    assert!(!view.confirmation.starts_with("approve "));
    assert!(view.diff.contains("-beta"));
    assert!(view.diff.contains("+alpha"));
    assert_ne!(view.digest, fx.proposal_digest);
    assert_eq!(view.digest.len(), 64);

    let model = fx.store.approve_restoration(
        &fx.sandbox,
        &limits(),
        &prepared.id,
        &view.digest,
        "restore the file to alpha",
    );
    assert_eq!(model.expect_err("model").kind(), "approval_rejected");
    let old = fx.store.approve_restoration(
        &fx.sandbox,
        &limits(),
        &prepared.id,
        &view.digest,
        &fx.proposal_line,
    );
    assert_eq!(old.expect_err("old approval").kind(), "approval_rejected");
    let reused = fx.store.approve(
        &fx.sandbox,
        &limits(),
        &fx.proposal_id,
        &fx.proposal_digest,
        &view.confirmation,
    );
    assert!(
        reused.is_err(),
        "restoration line must not apply the proposal"
    );
    assert_eq!(
        fs::read(fx.root.join("notes.txt")).expect("still torn"),
        fx.torn
    );

    let restored = fx
        .store
        .approve_restoration(
            &fx.sandbox,
            &limits(),
            &prepared.id,
            &view.digest,
            &view.confirmation,
        )
        .expect("restore");
    assert_eq!(restored.new_hash, view.summary.restored_sha256);
    assert_eq!(
        fs::read(fx.root.join("notes.txt")).expect("bytes"),
        b"alpha\n"
    );
    let status = fx
        .store
        .status_restoration(&fx.sandbox, &prepared.id)
        .expect("status");
    assert_eq!(status.state, "restored");
    assert_eq!(status.file_id, prepared.file_id);
    assert_eq!(status.attempt_phase, "verified");
    let again = fx.store.approve_restoration(
        &fx.sandbox,
        &limits(),
        &prepared.id,
        &view.digest,
        &view.confirmation,
    );
    assert_eq!(again.expect_err("second").kind(), "approval_consumed");
    assert_eq!(
        fs::read(fx.root.join("notes.txt")).expect("stable"),
        b"alpha\n"
    );
    assert_eq!(evidence_bytes(&fx.state), evidence_before);
    let log = audit_text(&fx.state);
    for event in [
        "restoration_prepared",
        "restoration_shown",
        "restoration_approved",
        "restoration_started",
        "restoration_verified",
        "restoration_restored",
    ] {
        assert!(
            log.contains(&format!("\"event\":\"{event}\"")),
            "{event} missing in {log}"
        );
    }
    assert!(!log.contains("alpha"));
    assert!(!log.contains("beta"));
    let _ = fs::remove_dir_all(&fx.root);
    let _ = fs::remove_dir_all(&fx.state);
}

#[test]
fn applied_conflict_and_clean_failure_are_not_restoration_sources() {
    let applied = saved("source-applied");
    let view = applied
        .store
        .show(&applied.sandbox, &applied.proposal_id)
        .expect("show");
    applied
        .store
        .approve(
            &applied.sandbox,
            &limits(),
            &applied.proposal_id,
            &view.digest,
            &view.confirmation,
        )
        .expect("apply");
    let error = applied
        .store
        .prepare_restoration(&applied.sandbox, &applied.proposal_id)
        .expect_err("applied");
    assert_eq!(error.kind(), "restoration_rejected");
    assert!(error.to_string().contains("applied"));
    assert_eq!(
        fs::read(applied.root.join("notes.txt")).expect("beta"),
        b"beta\n"
    );

    let conflict = saved("source-conflict");
    fs::write(conflict.root.join("notes.txt"), "gamma\n").expect("edit");
    let view = conflict
        .store
        .show(&conflict.sandbox, &conflict.proposal_id)
        .expect("show");
    let denied = conflict.store.approve(
        &conflict.sandbox,
        &limits(),
        &conflict.proposal_id,
        &view.digest,
        &view.confirmation,
    );
    assert!(denied.is_err());
    let error = conflict
        .store
        .prepare_restoration(&conflict.sandbox, &conflict.proposal_id)
        .expect_err("conflict");
    assert!(error.to_string().contains("conflict"));
    assert_eq!(
        fs::read(conflict.root.join("notes.txt")).expect("gamma"),
        b"gamma\n"
    );

    let failed = saved("source-failed");
    let view = failed
        .store
        .show(&failed.sandbox, &failed.proposal_id)
        .expect("show");
    let fault = failed.store.approve_with(
        &failed.sandbox,
        &limits(),
        &failed.proposal_id,
        &view.digest,
        &view.confirmation,
        ApplyFault::AfterIntent,
    );
    assert!(fault.is_err());
    let error = failed
        .store
        .prepare_restoration(&failed.sandbox, &failed.proposal_id)
        .expect_err("clean");
    assert!(error.to_string().contains("sealed original"));
    assert_eq!(
        fs::read(failed.root.join("notes.txt")).expect("alpha"),
        b"alpha\n"
    );
    let _ = fs::remove_dir_all(&applied.root);
    let _ = fs::remove_dir_all(&applied.state);
    let _ = fs::remove_dir_all(&conflict.root);
    let _ = fs::remove_dir_all(&conflict.state);
    let _ = fs::remove_dir_all(&failed.root);
    let _ = fs::remove_dir_all(&failed.state);
}

#[test]
fn changed_bytes_file_id_hardlink_and_reparse_are_rejected() {
    let fx = torn("changed");
    let view = prepare_view(&fx);
    fs::write(fx.root.join("notes.txt"), "gamma\n").expect("edit");
    let error = fx
        .store
        .approve_restoration(&fx.sandbox, &limits(), &view.0, &view.1, &view.2)
        .expect_err("changed");
    assert_eq!(error.kind(), "identity_changed");
    assert_eq!(
        fx.store
            .status_restoration(&fx.sandbox, &view.0)
            .expect("status")
            .state,
        "conflict"
    );
    assert_eq!(
        fs::read(fx.root.join("notes.txt")).expect("gamma"),
        b"gamma\n"
    );

    let swapped = torn("swap-id");
    let view = prepare_view(&swapped);
    let bytes = fs::read(swapped.root.join("notes.txt")).expect("torn");
    fs::remove_file(swapped.root.join("notes.txt")).expect("remove");
    fs::write(swapped.root.join("notes.txt"), &bytes).expect("recreate");
    let error = swapped
        .store
        .approve_restoration(&swapped.sandbox, &limits(), &view.0, &view.1, &view.2)
        .expect_err("file id");
    assert_eq!(error.kind(), "identity_changed");
    assert_eq!(
        fs::read(swapped.root.join("notes.txt")).expect("kept"),
        bytes
    );
    assert_ne!(bytes, b"alpha\n");

    let linked = torn("hardlink");
    let view = prepare_view(&linked);
    fs::hard_link(linked.root.join("notes.txt"), linked.root.join("alias.txt")).expect("link");
    let error = linked
        .store
        .approve_restoration(&linked.sandbox, &limits(), &view.0, &view.1, &view.2)
        .expect_err("hardlink");
    assert_eq!(error.kind(), "hardlink_denied");
    assert_eq!(
        fs::read(linked.root.join("notes.txt")).expect("kept"),
        linked.torn
    );
    assert_eq!(
        fs::read(linked.root.join("alias.txt")).expect("alias"),
        linked.torn
    );

    let reparsed = torn("junction");
    let view = prepare_view(&reparsed);
    let outside = temp_dir("junction-out");
    fs::write(outside.join("secret.txt"), "SENTINEL_OUTSIDE\n").expect("sentinel");
    fs::remove_file(reparsed.root.join("notes.txt")).expect("remove");
    let link = reparsed.root.join("notes.txt");
    let created = std::process::Command::new("cmd")
        .args([
            "/c",
            "mklink",
            "/J",
            &link.to_string_lossy(),
            &outside.to_string_lossy(),
        ])
        .status()
        .expect("mklink");
    assert!(created.success(), "junction");
    let error = reparsed
        .store
        .approve_restoration(&reparsed.sandbox, &limits(), &view.0, &view.1, &view.2)
        .expect_err("junction");
    assert!(
        error.kind() == "reparse_denied" || error.kind() == "not_a_file",
        "{error}"
    );
    assert_eq!(
        fs::read_to_string(outside.join("secret.txt")).expect("sentinel"),
        "SENTINEL_OUTSIDE\n"
    );
    let _ = fs::remove_dir(&link);
    match std::os::windows::fs::symlink_file(outside.join("secret.txt"), &link) {
        Ok(()) => {
            let _ = fs::remove_file(&link);
            let linked = torn("symlink");
            let view = prepare_view(&linked);
            fs::remove_file(linked.root.join("notes.txt")).expect("remove");
            std::os::windows::fs::symlink_file(
                outside.join("secret.txt"),
                linked.root.join("notes.txt"),
            )
            .expect("symlink");
            let error = linked
                .store
                .approve_restoration(&linked.sandbox, &limits(), &view.0, &view.1, &view.2)
                .expect_err("symlink");
            assert_eq!(error.kind(), "reparse_denied", "{error}");
            assert_eq!(
                fs::read_to_string(outside.join("secret.txt")).expect("sentinel"),
                "SENTINEL_OUTSIDE\n"
            );
            let _ = fs::remove_file(linked.root.join("notes.txt"));
            let _ = fs::remove_dir_all(&linked.root);
            let _ = fs::remove_dir_all(&linked.state);
        }
        Err(error) => {
            let code = error.raw_os_error();
            assert!(
                code == Some(1314) || code == Some(5),
                "symlink creation failed with an unexpected error: {error} ({code:?})"
            );
        }
    }

    let policy =
        lca_tools::PrivacyPolicy::try_from_patterns(&["notes.txt".to_owned()]).expect("policy");
    let private = torn("privacy");
    let blocked = WorkspaceSandbox::with_privacy(&private.root, policy).expect("sandbox");
    let error = private
        .store
        .prepare_restoration(&blocked, &private.proposal_id)
        .expect_err("privacy");
    assert_eq!(error.kind(), "privacy_denied");
    assert_eq!(
        fs::read(private.root.join("notes.txt")).expect("kept"),
        private.torn
    );

    let _ = fs::remove_dir_all(&fx.root);
    let _ = fs::remove_dir_all(&fx.state);
    let _ = fs::remove_dir_all(&swapped.root);
    let _ = fs::remove_dir_all(&swapped.state);
    let _ = fs::remove_dir_all(&linked.root);
    let _ = fs::remove_dir_all(&linked.state);
    let _ = fs::remove_dir_all(&reparsed.root);
    let _ = fs::remove_dir_all(&reparsed.state);
    let _ = fs::remove_dir_all(&private.root);
    let _ = fs::remove_dir_all(&private.state);
    let _ = fs::remove_dir_all(&outside);
}

#[test]
fn missing_and_manipulated_evidence_is_rejected() {
    let missing = torn("evidence-missing");
    let path = find_one(&missing.state, ".lcae");
    fs::remove_file(&path).expect("remove evidence");
    let error = missing
        .store
        .prepare_restoration(&missing.sandbox, &missing.proposal_id)
        .expect_err("missing");
    assert_eq!(error.kind(), "restoration_rejected");
    assert!(error.to_string().contains("missing"));

    let garbage = torn("evidence-garbage");
    let path = find_one(&garbage.state, ".lcae");
    fs::write(&path, b"not-a-dpapi-blob").expect("overwrite");
    let error = garbage
        .store
        .prepare_restoration(&garbage.sandbox, &garbage.proposal_id)
        .expect_err("garbage");
    assert_eq!(error.kind(), "restoration_rejected");
    assert!(error.to_string().contains("invalid"));

    let left = torn("evidence-left");
    let right = torn("evidence-right");
    let left_path = find_one(&left.state, ".lcae");
    let right_path = find_one(&right.state, ".lcae");
    let left_bytes = fs::read(&left_path).expect("left");
    fs::copy(&right_path, &left_path).expect("swap");
    let error = left
        .store
        .prepare_restoration(&left.sandbox, &left.proposal_id)
        .expect_err("wrong proposal");
    assert_eq!(error.kind(), "restoration_rejected");
    fs::write(&left_path, left_bytes).expect("restore evidence");
    left.store
        .prepare_restoration(&left.sandbox, &left.proposal_id)
        .expect("evidence restored");

    let tamper = torn("contract-tamper");
    let prepared = tamper
        .store
        .prepare_restoration(&tamper.sandbox, &tamper.proposal_id)
        .expect("prepare");
    let contract = find_one(&tamper.state, ".lcar");
    let plaintext =
        lca_platform::unprotect(&fs::read(&contract).expect("read")).expect("unprotect");
    let mut flipped = plaintext.clone();
    let index = flipped.len() / 2;
    flipped[index] ^= 0x01;
    if flipped[index] == plaintext[index] {
        flipped[index] ^= 0x02;
    }
    let protected = lca_platform::protect(&flipped).expect("protect");
    fs::write(&contract, protected).expect("write");
    let error = tamper
        .store
        .show_restoration(&tamper.sandbox, &prepared.id)
        .expect_err("tamper");
    assert_eq!(error.kind(), "restoration_rejected");

    let other = temp_dir("other-workspace");
    fs::write(other.join("notes.txt"), "alpha\n").expect("seed");
    let other_sandbox = WorkspaceSandbox::new(&other).expect("sandbox");
    let error = tamper
        .store
        .show_restoration(&other_sandbox, &prepared.id)
        .expect_err("workspace");
    assert!(
        error.kind() == "restoration_rejected" || error.kind() == "workspace_mismatch",
        "{error}"
    );

    let _ = fs::remove_dir_all(&missing.root);
    let _ = fs::remove_dir_all(&missing.state);
    let _ = fs::remove_dir_all(&garbage.root);
    let _ = fs::remove_dir_all(&garbage.state);
    let _ = fs::remove_dir_all(&left.root);
    let _ = fs::remove_dir_all(&left.state);
    let _ = fs::remove_dir_all(&right.root);
    let _ = fs::remove_dir_all(&right.state);
    let _ = fs::remove_dir_all(&tamper.root);
    let _ = fs::remove_dir_all(&tamper.state);
    let _ = fs::remove_dir_all(&other);
}

#[test]
fn a_rejected_restoration_and_a_publish_fault_do_not_rewrite() {
    let fx = torn("reject");
    let view = prepare_view(&fx);
    let rejected = fx
        .store
        .reject_restoration(&fx.sandbox, &view.0)
        .expect("reject");
    assert_eq!(rejected.state, "rejected");
    let error = fx
        .store
        .approve_restoration(&fx.sandbox, &limits(), &view.0, &view.1, &view.2)
        .expect_err("rejected");
    assert_eq!(error.kind(), "approval_consumed");
    assert_eq!(fs::read(fx.root.join("notes.txt")).expect("kept"), fx.torn);
    let log = audit_text(&fx.state);
    assert!(log.contains("restoration_rejected"), "{log}");

    let partial = torn("partial-write");
    fs::write(
        partial.root.join("notes.txt"),
        [partial.torn.as_slice(), b"TAIL"].concat(),
    )
    .expect("extend");
    let extended = fs::read(partial.root.join("notes.txt")).expect("extended");
    let view = prepare_view(&partial);
    let error = partial
        .store
        .approve_restoration_with(
            &partial.sandbox,
            &limits(),
            &view.0,
            &view.1,
            &view.2,
            ApplyFault::DuringPublish,
        )
        .expect_err("fault");
    assert_eq!(error.kind(), "fault_injected");
    let bytes = fs::read(partial.root.join("notes.txt")).expect("bytes");
    assert_ne!(bytes, b"alpha\n");
    assert_ne!(bytes, extended);
    let before = bytes.clone();
    let status = partial
        .store
        .status_restoration(&partial.sandbox, &view.0)
        .expect("status");
    assert_eq!(status.state, "unclear");
    let recovered = partial
        .store
        .recover_restoration(&partial.sandbox, &view.0)
        .expect("recover");
    assert_eq!(recovered.state, "unclear");
    assert_eq!(
        fs::read(partial.root.join("notes.txt")).expect("stable"),
        before
    );
    let again =
        partial
            .store
            .approve_restoration(&partial.sandbox, &limits(), &view.0, &view.1, &view.2);
    assert!(again.is_err());
    assert_eq!(
        fs::read(partial.root.join("notes.txt")).expect("untouched"),
        before
    );
    assert!(find_one(&partial.state, ".lcae").exists());

    let _ = fs::remove_dir_all(&fx.root);
    let _ = fs::remove_dir_all(&fx.state);
    let _ = fs::remove_dir_all(&partial.root);
    let _ = fs::remove_dir_all(&partial.state);
}

struct Fix {
    root: PathBuf,
    state: PathBuf,
    sandbox: WorkspaceSandbox,
    store: ProposalStore,
    proposal_id: String,
    proposal_digest: String,
    proposal_line: String,
    torn: Vec<u8>,
}

fn torn(label: &str) -> Fix {
    let fx = saved(label);
    let view = fx.store.show(&fx.sandbox, &fx.proposal_id).expect("show");
    let error = fx.store.approve_with(
        &fx.sandbox,
        &limits(),
        &fx.proposal_id,
        &view.digest,
        &view.confirmation,
        ApplyFault::DuringPublish,
    );
    assert!(error.is_err(), "{label}");
    let torn_bytes = fs::read(fx.root.join("notes.txt")).expect("torn");
    assert_ne!(torn_bytes, b"alpha\n");
    assert_ne!(torn_bytes, b"beta\n");
    let _ = fx.store.recover(&fx.sandbox, &fx.proposal_id);
    Fix {
        torn: torn_bytes,
        proposal_digest: view.digest,
        proposal_line: view.confirmation,
        ..fx
    }
}

fn saved(label: &str) -> Fix {
    let root = temp_dir(label);
    let state = temp_dir(&format!("{label}-store"));
    fs::write(root.join("notes.txt"), "alpha\n").expect("seed");
    let sandbox = WorkspaceSandbox::new(&root).expect("sandbox");
    let store = ProposalStore::open(&state).expect("store");
    let prepared = prepare(&sandbox);
    let saved = store.save(&sandbox, &prepared).expect("save");
    let view = store.show(&sandbox, &saved.id).expect("show");
    Fix {
        root,
        state,
        sandbox,
        store,
        proposal_id: saved.id,
        proposal_digest: view.digest,
        proposal_line: view.confirmation,
        torn: b"alpha\n".to_vec(),
    }
}

fn prepare_view(fx: &Fix) -> (String, String, String) {
    let prepared = fx
        .store
        .prepare_restoration(&fx.sandbox, &fx.proposal_id)
        .expect("prepare");
    let view = fx
        .store
        .show_restoration(&fx.sandbox, &prepared.id)
        .expect("show");
    (prepared.id, view.digest, view.confirmation)
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

fn evidence_bytes(root: &Path) -> Vec<u8> {
    fs::read(find_one(root, ".lcae")).expect("evidence")
}

fn find_one(root: &Path, suffix: &str) -> PathBuf {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(suffix))
            {
                found.push(path);
            }
        }
    }
    assert_eq!(found.len(), 1, "{suffix} in {root:?}: {found:?}");
    found.pop().expect("one")
}

fn audit_text(root: &Path) -> String {
    let mut out = String::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().and_then(|name| name.to_str()) == Some("events.log") {
                out.push_str(&fs::read_to_string(&path).unwrap_or_default());
            }
        }
    }
    out
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "lca-restore-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("temp");
    path
}
