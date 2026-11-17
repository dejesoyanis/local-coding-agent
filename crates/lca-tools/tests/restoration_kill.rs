//! Child-process kill tests for restoration.
//!
//! The parent creates a torn file, prepares a restoration, and terminates the child with
//! `taskkill /F`. Recovery reads the store. It does not write the target again.

#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lca_tools::{
    ActionIdFactory, ActionSource, ApplyFault, FsLimitValues, FsLimits, FsOutcome, KillHold,
    ProposalStore, ToolRegistry, WorkspaceSandbox, execute_validated, propose_actions,
    validate_batch,
};
use serde_json::json;

#[test]
fn restoration_kill_child() {
    let Ok(path) = std::env::var("LCA_RESTORE_KILL_SPEC") else {
        return;
    };
    let spec = fs::read_to_string(&path).expect("spec");
    let spec: serde_json::Value = serde_json::from_str(&spec).expect("json");
    let workspace = PathBuf::from(spec["workspace"].as_str().expect("workspace"));
    let state = PathBuf::from(spec["state"].as_str().expect("state"));
    let ready = PathBuf::from(spec["ready"].as_str().expect("ready"));
    let point = ApplyFault::from_name(spec["point"].as_str().expect("point")).expect("point");
    let sandbox = WorkspaceSandbox::new(&workspace).expect("sandbox");
    let store = ProposalStore::open(&state).expect("store");
    let hold = KillHold::new(point, ready);
    let result = store.approve_restoration_holding(
        &sandbox,
        &limits(),
        spec["id"].as_str().expect("id"),
        spec["digest"].as_str().expect("digest"),
        spec["line"].as_str().expect("line"),
        &hold,
    );
    let message = match result {
        Ok(_) => "hold returned success".to_owned(),
        Err(error) => error.to_string(),
    };
    let _ = fs::write(
        PathBuf::from(spec["error"].as_str().expect("error")),
        message,
    );
    std::process::exit(2);
}

#[test]
fn killed_restoration_is_not_retried() {
    if std::env::var_os("LCA_RESTORE_KILL_SPEC").is_some() {
        return;
    }
    let cases = [
        ("after_validation", "torn", "prepared", false),
        ("after_approval", "torn", "approved", true),
        ("after_intent", "torn", "failed", true),
        ("before_flush", "alpha\n", "restored", true),
        ("after_rename", "alpha\n", "restored", true),
        ("before_readback", "alpha\n", "restored", true),
        ("after_verification", "alpha\n", "restored", true),
        ("before_audit", "alpha\n", "restored", true),
    ];
    for (point, expected, state, consumed) in cases {
        kill_case(point, expected, state, consumed, false);
    }
    kill_case("during_publish", "partial", "unclear", true, true);
}

fn kill_case(point: &str, expected: &str, state: &str, consumed: bool, extend: bool) {
    let root = temp_dir("kill-ws");
    let store_root = temp_dir("kill-store");
    fs::write(root.join("notes.txt"), "alpha\n").expect("seed");
    let sandbox = WorkspaceSandbox::new(&root).expect("sandbox");
    let store = ProposalStore::open(&store_root).expect("store");
    let prepared = prepare(&sandbox);
    let saved = store.save(&sandbox, &prepared).expect("save");
    let proposal = store.show(&sandbox, &saved.id).expect("show");
    let torn = store.approve_with(
        &sandbox,
        &limits(),
        &saved.id,
        &proposal.digest,
        &proposal.confirmation,
        ApplyFault::DuringPublish,
    );
    assert!(torn.is_err(), "{point}");
    let _ = store.recover(&sandbox, &saved.id);
    if extend {
        let mut bytes = fs::read(root.join("notes.txt")).expect("torn");
        bytes.extend_from_slice(b"TAIL");
        fs::write(root.join("notes.txt"), &bytes).expect("extend");
    }
    let torn_bytes = fs::read(root.join("notes.txt")).expect("torn");
    let restoration = store
        .prepare_restoration(&sandbox, &saved.id)
        .expect("prepare");
    let view = store
        .show_restoration(&sandbox, &restoration.id)
        .expect("show");
    let evidence = fs::read(find_one(&store_root, ".lcae")).expect("evidence");
    let file_id = restoration.file_id.clone();
    let ready = root.join("ready");
    let error_path = root.join("child-error.txt");
    let spec = store_root.join("spec.json");
    fs::write(
        &spec,
        serde_json::to_string(&json!({
            "workspace": root,
            "state": store_root,
            "id": restoration.id,
            "digest": view.digest,
            "line": view.confirmation,
            "point": point,
            "ready": ready,
            "error": error_path,
        }))
        .expect("spec"),
    )
    .expect("write spec");
    let mut child = Command::new(std::env::current_exe().expect("exe"))
        .arg("restoration_kill_child")
        .arg("--exact")
        .env("LCA_RESTORE_KILL_SPEC", &spec)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn");
    let started = Instant::now();
    loop {
        if ready.exists() {
            break;
        }
        if child.try_wait().expect("poll").is_some() {
            let detail = fs::read_to_string(&error_path).unwrap_or_default();
            panic!("{point} exited before the hold: {detail}");
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!("{point} did not reach the hold");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(child.try_wait().expect("alive").is_none(), "{point}");
    let blocked = store.prepare_restoration(&sandbox, &saved.id);
    assert!(blocked.is_err(), "{point} opened a second restoration");
    let killed = Command::new("taskkill")
        .args(["/F", "/PID", &child.id().to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("taskkill");
    assert!(killed.success(), "{point}");
    let finished = child.wait().expect("wait");
    assert!(!finished.success(), "{point} survived taskkill: {finished}");
    let before = fs::read(root.join("notes.txt")).expect("bytes");
    match expected {
        "torn" => assert_eq!(before, torn_bytes, "{point}"),
        "alpha\n" => assert_eq!(before, b"alpha\n", "{point}"),
        "partial" => {
            assert_ne!(before, torn_bytes, "{point}");
            assert_ne!(before, b"alpha\n", "{point}");
        }
        _ => unreachable!("case"),
    }
    let started_before = count_event(&store_root, "restoration_started");
    if point == "after_validation" || point == "after_approval" {
        assert_eq!(started_before, 0, "{point}");
    } else {
        assert_eq!(started_before, 1, "{point}");
    }
    let report = store
        .recover_restoration(&sandbox, &restoration.id)
        .expect("recover");
    let after = fs::read(root.join("notes.txt")).expect("after");
    assert_eq!(after, before, "{point} recovery rewrote the file");
    assert_eq!(report.state, state, "{point}");
    assert_eq!(report.file_id, file_id, "{point}");
    assert_eq!(
        fs::read(find_one(&store_root, ".lcae")).expect("evidence"),
        evidence
    );
    assert_eq!(
        count_event(&store_root, "restoration_started"),
        started_before,
        "{point}"
    );
    if consumed {
        let again = store.approve_restoration(
            &sandbox,
            &limits(),
            &restoration.id,
            &view.digest,
            &view.confirmation,
        );
        assert!(again.is_err(), "{point} reused the restoration approval");
        assert_eq!(fs::read(root.join("notes.txt")).expect("final"), before);
    }
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&store_root);
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

fn count_event(root: &Path, event: &str) -> usize {
    let mut count = 0usize;
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
                let text = fs::read_to_string(&path).unwrap_or_default();
                count += text.matches(&format!("\"event\":\"{event}\"")).count();
            }
        }
    }
    count
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
    assert_eq!(found.len(), 1, "{suffix}");
    found.pop().expect("one")
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path =
        std::env::temp_dir().join(format!("lca-rkill-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).expect("temp");
    path
}
