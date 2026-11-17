//! Child-process kill tests for publication recovery.
//!
//! The parent creates a temporary workspace, starts this test binary again, and terminates
//! that process with `taskkill /F`. Recovery then reads the store. It does not rewrite the file.

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
fn kill_child() {
    let Ok(path) = std::env::var("LCA_KILL_SPEC") else {
        return;
    };
    let spec = std::fs::read_to_string(&path).expect("spec");
    let spec: serde_json::Value = serde_json::from_str(&spec).expect("json");
    let workspace = PathBuf::from(spec["workspace"].as_str().expect("workspace"));
    let state = PathBuf::from(spec["state"].as_str().expect("state"));
    let ready = PathBuf::from(spec["ready"].as_str().expect("ready"));
    let point = ApplyFault::from_name(spec["point"].as_str().expect("point")).expect("point");
    let sandbox = WorkspaceSandbox::new(&workspace).expect("sandbox");
    let store = ProposalStore::open(&state).expect("store");
    let hold = KillHold::new(point, ready);
    let result = store.approve_holding(
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
    let _ = std::fs::write(
        PathBuf::from(spec["error"].as_str().expect("error")),
        message,
    );
    std::process::exit(2);
}

#[test]
fn killed_child_is_recovered_without_a_rewrite() {
    if std::env::var_os("LCA_KILL_SPEC").is_some() {
        return;
    }
    let cases = [
        ("after_intent", "alpha\n", "failed"),
        ("after_temp_create", "alpha\n", "failed"),
        ("after_write", "alpha\n", "failed"),
        ("after_stage_flush", "alpha\n", "failed"),
        ("before_rename", "alpha\n", "failed"),
        ("during_publish", "torn", "unclear"),
        ("before_flush", "beta\n", "applied"),
        ("after_rename", "beta\n", "applied"),
        ("before_readback", "beta\n", "applied"),
        ("after_verification", "beta\n", "applied"),
        ("before_audit", "beta\n", "applied"),
    ];
    for (point, expected, state) in cases {
        let root = temp_dir("kill-ws");
        let store_root = temp_dir("kill-store");
        let ready = root.join("ready");
        let error_path = root.join("child-error.txt");
        std::fs::write(root.join("notes.txt"), "alpha\n").expect("seed");
        let sandbox = WorkspaceSandbox::new(&root).expect("sandbox");
        let prepared = prepare(&sandbox);
        let store = ProposalStore::open(&store_root).expect("store");
        let saved = store.save(&sandbox, &prepared).expect("save");
        let view = store.show(&sandbox, &saved.id).expect("show");
        let spec = store_root.join("spec.json");
        std::fs::write(
            &spec,
            serde_json::to_string(&json!({
                "workspace": root,
                "state": store_root,
                "id": saved.id,
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
            .arg("kill_child")
            .arg("--exact")
            .env("LCA_KILL_SPEC", &spec)
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
                let detail = std::fs::read_to_string(&error_path).unwrap_or_default();
                panic!("{point} exited before the hold: {detail}");
            }
            if started.elapsed() > Duration::from_secs(60) {
                let _ = child.kill();
                panic!("{point} did not reach the hold");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            child.try_wait().expect("still alive").is_none(),
            "{point} exited on its own"
        );
        let killed = Command::new("taskkill")
            .args(["/F", "/PID", &child.id().to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("taskkill");
        assert!(killed.success(), "{point} was not terminated");
        let finished = child.wait().expect("wait");
        assert!(!finished.success(), "{point} survived taskkill: {finished}");
        let before = std::fs::read(root.join("notes.txt")).expect("bytes");
        match expected {
            "alpha\n" => assert_eq!(before, b"alpha\n", "{point}"),
            "beta\n" => assert_eq!(before, b"beta\n", "{point}"),
            "torn" => {
                assert_ne!(before, b"alpha\n", "{point}");
                assert_ne!(before, b"beta\n", "{point}");
            }
            _ => unreachable!("case"),
        }
        let started_before = count_event(&store_root, "apply_started");
        assert_eq!(started_before, 1, "{point}");
        let report = store.recover(&sandbox, &saved.id).expect("recover");
        let after = std::fs::read(root.join("notes.txt")).expect("after");
        assert_eq!(after, before, "{point} recovery rewrote the file");
        assert_eq!(report.stored_state, state, "{point}");
        assert_eq!(report.current_file_id, report.recorded_file_id, "{point}");
        assert_eq!(report.strategy, "pinned_in_place", "{point}");
        assert_eq!(count_event(&store_root, "apply_started"), 1, "{point}");
        let again = store.approve(
            &sandbox,
            &limits(),
            &saved.id,
            &view.digest,
            &view.confirmation,
        );
        assert!(again.is_err(), "{point} reused the approval");
        assert_eq!(
            std::fs::read(root.join("notes.txt")).expect("final"),
            before
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&store_root);
    }
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
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().and_then(|name| name.to_str()) == Some("events.log") {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                count += text.matches(&format!("\"event\":\"{event}\"")).count();
            }
        }
    }
    count
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path =
        std::env::temp_dir().join(format!("lca-kill-{label}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).expect("temp");
    path
}
