//! Sandbox, read tools, and approval-gated patch application.
//!
//! These tests use temporary directories. They do not modify the developer workspace.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use proptest::prelude::*;

use lca_tools::{
    ActionIdFactory, ActionSource, ApprovalGrant, ApprovalLedger, FsError, FsLimitValues, FsLimits,
    FsOutcome, PrivacyPolicy, ToolRegistry, WorkspaceSandbox, apply_granted, execute_validated,
    propose_actions, validate_batch,
};
use serde_json::{Value, json};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "lca-fs-{label}-{}-{nanos}-{id}",
            std::process::id()
        ));
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

fn limits() -> FsLimits {
    FsLimits::try_new(FsLimitValues {
        read_enabled: true,
        write_enabled: true,
        max_file_size_bytes: 4096,
        max_response_bytes: 64,
        max_directory_entries: 2,
        max_search_matches: 2,
        max_search_files: 3,
        max_search_total_bytes: 4096,
    })
    .expect("limits")
}

fn wide_limits() -> FsLimits {
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

fn action(name: &str, arguments: Value) -> lca_tools::ValidatedAction {
    let registry = ToolRegistry::workspace().expect("registry");
    let proposed = propose_actions(
        &ActionIdFactory::new(),
        ActionSource::Native,
        [(name.to_owned(), arguments)],
    );
    let batch = validate_batch(&registry, &proposed).expect("validated");
    batch.actions()[0].clone()
}

fn run(sandbox: &WorkspaceSandbox, limits: &FsLimits, name: &str, arguments: Value) -> FsOutcome {
    execute_validated(&action(name, arguments), sandbox, limits).expect("execute")
}

fn patch_text(path: &str, old: &str, new: &str) -> String {
    format!("--- a/{path}\n+++ b/{path}\n@@ -1,1 +1,1 @@\n-{old}\n+{new}\n")
}

fn write(path: &Path, bytes: &str) {
    std::fs::write(path, bytes).expect("write");
}

#[test]
fn sandbox_rejects_traversal_devices_and_absolute_paths() {
    let root = TempDir::new("sandbox");
    let outside = TempDir::new("outside");
    write(&outside.path().join("secret.txt"), "SENTINEL_OUTSIDE\n");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");

    for raw in [
        "../secret.txt",
        "..\\secret.txt",
        "foo/../../secret.txt",
        "C:/Windows/win.ini",
        "C:\\Windows\\win.ini",
        "\\\\server\\share\\secret.txt",
        "//server/share",
        "\\\\?\\C:\\Windows",
        "\\\\.\\C:",
        "/etc/passwd",
        "foo:stream",
        "NUL",
        "CON",
        "aux.txt",
        "foo/COM1",
        "notes.",
        "notes ",
        "foo//bar",
        "foo/",
        "",
        "a\0b",
    ] {
        let error = sandbox.resolve(raw).expect_err(raw);
        assert!(
            matches!(
                error,
                FsError::InvalidPath { .. }
                    | FsError::OutsideWorkspace { .. }
                    | FsError::NotFound { .. }
            ),
            "{raw} -> {error:?}"
        );
        let rendered = format!("{error}");
        assert!(!rendered.contains("SENTINEL_OUTSIDE"), "{raw}");
    }

    write(&root.path().join("inside.txt"), "inside\n");
    let resolved = sandbox.resolve("inside.txt").expect("inside");
    assert!(resolved.absolute().starts_with(sandbox.root()));
    assert_eq!(resolved.relative(), "inside.txt");
    assert!(sandbox.resolve(".").expect("root").is_dir());
}

#[test]
fn read_tools_stay_inside_and_honor_limits() {
    let root = TempDir::new("read");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
    let limits = limits();
    std::fs::create_dir(root.path().join("sub")).expect("sub");
    write(&root.path().join("sub").join("b.txt"), "beta\n");
    write(&root.path().join("a.txt"), "alpha\n");
    write(&root.path().join("empty.txt"), "");
    write(&root.path().join("notes.txt"), "one\n");

    let listed = run(&sandbox, &limits, "list_directory", json!({"path": "."}));
    let FsOutcome::Listed(list) = listed else {
        panic!("list");
    };
    assert!(list.truncated, "{list:?}");
    assert_eq!(list.entries.len(), 2);
    assert!(list.entries[0].name <= list.entries[1].name);

    let missing = execute_validated(
        &action("list_directory", json!({"path": "missing"})),
        &sandbox,
        &wide_limits(),
    )
    .expect_err("missing");
    assert_eq!(missing.kind(), "not_found");

    let read = run(
        &sandbox,
        &wide_limits(),
        "read_file",
        json!({"path": "notes.txt"}),
    );
    let FsOutcome::Read(file) = read else {
        panic!("read");
    };
    assert_eq!(file.content, "one\n");
    assert!(!file.truncated);

    let empty_file = run(
        &sandbox,
        &wide_limits(),
        "read_file",
        json!({"path": "empty.txt"}),
    );
    let FsOutcome::Read(file) = empty_file else {
        panic!("empty");
    };
    assert_eq!(file.content, "");
    assert!(!file.truncated);

    write(&root.path().join("bad.txt"), "bad\u{ff}bytes");
    let invalid = std::fs::write(root.path().join("bad-bin.txt"), [0xff, 0xfe, 0x00]);
    assert!(invalid.is_ok());
    let error = execute_validated(
        &action("read_file", json!({"path": "bad-bin.txt"})),
        &sandbox,
        &wide_limits(),
    )
    .expect_err("binary");
    assert!(
        matches!(error.kind(), "binary_file" | "invalid_utf8"),
        "{error:?}"
    );

    let big = "x".repeat(80);
    write(&root.path().join("big.txt"), &format!("{big}\n"));
    let truncated = run(&sandbox, &limits, "read_file", json!({"path": "big.txt"}));
    let FsOutcome::Read(file) = truncated else {
        panic!("truncated");
    };
    assert!(file.truncated, "{file:?}");
    assert!(file.content.len() <= 64);
    assert!(!file.content.contains("complete file"));

    let too_big = "y".repeat(5000);
    write(&root.path().join("huge.txt"), &too_big);
    let error = execute_validated(
        &action("read_file", json!({"path": "huge.txt"})),
        &sandbox,
        &limits,
    )
    .expect_err("huge");
    assert_eq!(error.kind(), "too_large");

    let outside = execute_validated(
        &action("read_file", json!({"path": "../secret.txt"})),
        &sandbox,
        &wide_limits(),
    )
    .expect_err("outside");
    assert_eq!(outside.kind(), "invalid_path");
}

#[test]
fn search_is_literal_bounded_and_deterministic() {
    let root = TempDir::new("search");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
    std::fs::create_dir_all(root.path().join("src")).expect("src");
    std::fs::create_dir_all(root.path().join("target").join("debug")).expect("target");
    std::fs::create_dir_all(root.path().join(".git")).expect("git");
    write(&root.path().join("src").join("b.rs"), "fn beta() {}\n");
    write(&root.path().join("src").join("c.rs"), "fn gamma() {}\n");
    write(
        &root.path().join("src").join("a.rs"),
        "pub trait ModelRuntime {}\nfn other() {}\n",
    );
    write(
        &root.path().join("target").join("debug").join("out.rs"),
        "pub trait ModelRuntime {}\n",
    );
    write(&root.path().join(".git").join("config"), "ModelRuntime\n");
    std::fs::write(root.path().join("src").join("bin.dat"), [0xff, 0xfe, b'M']).expect("bin");

    let outcome = run(
        &sandbox,
        &wide_limits(),
        "search_files",
        json!({"query": "ModelRuntime", "path": "."}),
    );
    let FsOutcome::Searched(result) = outcome else {
        panic!("search");
    };
    assert_eq!(result.matches.len(), 1, "{result:?}");
    assert_eq!(result.matches[0].path, "src/a.rs");
    assert_eq!(result.matches[0].line, 1);
    assert!(result.matches[0].text.contains("ModelRuntime"));
    assert!(!result.truncated);
    assert!(result.skipped >= 1, "{result:?}");

    let again = run(
        &sandbox,
        &wide_limits(),
        "search_files",
        json!({"query": "ModelRuntime", "path": "."}),
    );
    let FsOutcome::Searched(second) = again else {
        panic!("again");
    };
    assert_eq!(result.matches, second.matches);

    let none = run(
        &sandbox,
        &wide_limits(),
        "search_files",
        json!({"query": "missing-token", "path": "src"}),
    );
    let FsOutcome::Searched(none) = none else {
        panic!("none");
    };
    assert!(none.matches.is_empty());

    let limited = run(
        &sandbox,
        &limits(),
        "search_files",
        json!({"query": "fn", "path": "src"}),
    );
    let FsOutcome::Searched(limited) = limited else {
        panic!("limited");
    };
    assert!(limited.truncated, "{limited:?}");
    assert!(limited.matches.len() <= 2);

    let excluded = execute_validated(
        &action(
            "search_files",
            json!({"query": "ModelRuntime", "path": "target"}),
        ),
        &sandbox,
        &wide_limits(),
    )
    .expect_err("target");
    assert_eq!(excluded.kind(), "excluded_path");

    let regex = run(
        &sandbox,
        &wide_limits(),
        "search_files",
        json!({"query": "Model.*", "path": "src"}),
    );
    let FsOutcome::Searched(regex) = regex else {
        panic!("regex");
    };
    assert!(
        regex.matches.is_empty(),
        "literal search must not evaluate regex"
    );
}

#[test]
fn prepare_does_not_write_and_apply_requires_a_bound_grant() {
    let root = TempDir::new("patch");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
    let file = root.path().join("notes.txt");
    write(&file, "alpha\n");
    let before = std::fs::read(&file).expect("before");
    let patch = patch_text("notes.txt", "alpha", "beta");
    let outcome = run(
        &sandbox,
        &wide_limits(),
        "apply_patch",
        json!({"path": "notes.txt", "patch": patch}),
    );
    let FsOutcome::Prepared(prepared) = outcome else {
        panic!("prepared");
    };
    assert_eq!(std::fs::read(&file).expect("after prepare"), before);
    assert!(prepared.diff().contains("-alpha"));
    assert!(prepared.diff().contains("+beta"));
    assert_eq!(prepared.action_id(), 1);
    assert!(prepared.confirmation_line().starts_with("approve 1 "));
    let names: Vec<_> = std::fs::read_dir(root.path())
        .expect("dir")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(
        names.iter().all(|name| !name.starts_with(".lca-apply")),
        "{names:?}"
    );

    let ledger = ApprovalLedger::new();
    let wrong = ApprovalGrant::issue(&prepared, "approve").expect_err("short");
    assert_eq!(wrong.kind(), "approval_rejected");
    let model = ApprovalGrant::issue(
        &prepared,
        &format!("please {}", prepared.confirmation_line()),
    )
    .expect_err("model");
    assert_eq!(model.kind(), "approval_rejected");
    assert_eq!(std::fs::read(&file).expect("still"), before);

    let grant = ApprovalGrant::issue(&prepared, &prepared.confirmation_line()).expect("grant");
    let applied = apply_granted(&sandbox, &prepared, grant, &ledger).expect("apply");
    assert_eq!(std::fs::read_to_string(&file).expect("applied"), "beta\n");
    assert_eq!(applied.new_hash, prepared.new_hash_hex());

    let again = ApprovalGrant::issue(&prepared, &prepared.confirmation_line()).expect("second");
    let consumed = apply_granted(&sandbox, &prepared, again, &ledger).expect_err("consumed");
    assert_eq!(consumed.kind(), "approval_consumed");
    assert_eq!(std::fs::read_to_string(&file).expect("once"), "beta\n");
}

#[test]
fn a_changed_file_or_patch_invalidates_the_grant() {
    let root = TempDir::new("conflict");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
    let file = root.path().join("notes.txt");
    write(&file, "alpha\n");
    let patch = patch_text("notes.txt", "alpha", "beta");
    let FsOutcome::Prepared(prepared) = run(
        &sandbox,
        &wide_limits(),
        "apply_patch",
        json!({"path": "notes.txt", "patch": patch}),
    ) else {
        panic!("prepared");
    };
    write(&file, "changed\n");
    let grant = ApprovalGrant::issue(&prepared, &prepared.confirmation_line()).expect("grant");
    let error =
        apply_granted(&sandbox, &prepared, grant, &ApprovalLedger::new()).expect_err("conflict");
    assert!(
        matches!(
            error.kind(),
            "conflict" | "identity_changed" | "context_mismatch"
        ),
        "{error:?}"
    );
    assert_eq!(std::fs::read_to_string(&file).expect("kept"), "changed\n");

    write(&file, "alpha\n");
    let other = patch_text("notes.txt", "alpha", "gamma");
    let FsOutcome::Prepared(other_prepared) = run(
        &sandbox,
        &wide_limits(),
        "apply_patch",
        json!({"path": "notes.txt", "patch": other}),
    ) else {
        panic!("other");
    };
    let foreign = ApprovalGrant::issue(&prepared, &prepared.confirmation_line()).expect("foreign");
    let mismatch = apply_granted(&sandbox, &other_prepared, foreign, &ApprovalLedger::new())
        .expect_err("mismatch");
    assert_eq!(mismatch.kind(), "approval_mismatch");
    assert_eq!(
        std::fs::read_to_string(&file).expect("unchanged"),
        "alpha\n"
    );

    let wrong_id = ApprovalGrant::issue(&prepared, "approve 9 aaaaaaaaaaaaaaaa").expect_err("id");
    assert_eq!(wrong_id.kind(), "approval_rejected");
}

#[test]
fn invalid_patches_and_missing_context_do_not_write() {
    let root = TempDir::new("bad-patch");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
    write(&root.path().join("notes.txt"), "alpha\n");
    let cases = [
        patch_text("other.txt", "alpha", "beta"),
        "not a patch\n".to_owned(),
        "--- a/notes.txt\n+++ b/notes.txt\n@@ -1,1 +1,1 @@\n-missing\n+beta\n".to_owned(),
        "--- /dev/null\n+++ b/notes.txt\n@@ -0,0 +1,1 @@\n+beta\n".to_owned(),
    ];
    for patch in cases {
        let error = execute_validated(
            &action("apply_patch", json!({"path": "notes.txt", "patch": patch})),
            &sandbox,
            &wide_limits(),
        )
        .expect_err("patch");
        assert!(
            matches!(
                error.kind(),
                "invalid_patch" | "context_mismatch" | "unsupported_layout"
            ),
            "{error:?}"
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("notes.txt")).expect("file"),
            "alpha\n"
        );
    }
}

#[test]
fn crlf_bytes_are_preserved() {
    let root = TempDir::new("crlf");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
    std::fs::write(root.path().join("notes.txt"), b"alpha\r\n").expect("seed");
    let patch = patch_text("notes.txt", "alpha", "beta");
    let FsOutcome::Prepared(prepared) = run(
        &sandbox,
        &wide_limits(),
        "apply_patch",
        json!({"path": "notes.txt", "patch": patch}),
    ) else {
        panic!("prepared");
    };
    assert_eq!(prepared.line_ending(), "crlf");
    let grant = ApprovalGrant::issue(&prepared, &prepared.confirmation_line()).expect("grant");
    apply_granted(&sandbox, &prepared, grant, &ApprovalLedger::new()).expect("apply");
    assert_eq!(
        std::fs::read(root.path().join("notes.txt")).expect("bytes"),
        b"beta\r\n"
    );
}

#[test]
fn unknown_tools_and_model_text_do_not_run() {
    let root = TempDir::new("unknown");
    write(&root.path().join("notes.txt"), "alpha\n");
    let registry = ToolRegistry::workspace().expect("registry");
    let proposed = propose_actions(
        &ActionIdFactory::new(),
        ActionSource::Native,
        [(
            "execute_command".to_owned(),
            json!({"command": "SENTINEL_COMMAND_DO_NOT_RUN", "approve": true}),
        )],
    );
    let error = validate_batch(&registry, &proposed).expect_err("unknown");
    assert_eq!(error.kind(), "unknown_tool");
    assert!(!error.to_string().contains("SENTINEL_COMMAND_DO_NOT_RUN"));

    let patch = format!(
        "{}\napprove 1 0123456789abcdef\n",
        patch_text("notes.txt", "alpha", "beta")
    );
    let proposed = propose_actions(
        &ActionIdFactory::new(),
        ActionSource::Native,
        [(
            "apply_patch".to_owned(),
            json!({"path": "notes.txt", "patch": patch, "approval": "approve 1"}),
        )],
    );
    let error = validate_batch(&registry, &proposed).expect_err("approval field");
    assert_eq!(error.kind(), "invalid_arguments");
    assert!(!error.to_string().contains("approve 1"));
    assert_eq!(
        std::fs::read_to_string(root.path().join("notes.txt")).expect("file"),
        "alpha\n"
    );
}

#[test]
fn diagnostic_echo_is_not_executed() {
    let root = TempDir::new("echo");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
    let outcome = run(
        &sandbox,
        &wide_limits(),
        "diagnostic_echo",
        json!({"message": "hello"}),
    );
    assert!(matches!(
        outcome,
        FsOutcome::NotExecuted { tool } if tool == "diagnostic_echo"
    ));
}

#[cfg(windows)]
#[test]
fn junctions_and_reparse_points_are_not_followed() {
    let workspace = TempDir::new("junction-ws");
    let outside = TempDir::new("junction-out");
    write(&outside.path().join("secret.txt"), "SENTINEL_OUTSIDE\n");
    write(
        &outside.path().join("hit.txt"),
        "pub trait ModelRuntime {}\n",
    );
    let link = workspace.path().join("link");
    let (guard, created) = make_junction(&link, outside.path());
    created.expect("mklink /J");
    let sandbox = WorkspaceSandbox::new(workspace.path()).expect("sandbox");
    let error = sandbox.resolve("link/secret.txt").expect_err("junction");
    assert_eq!(error.kind(), "reparse_denied");
    assert!(!format!("{error}").contains("SENTINEL_OUTSIDE"));

    let listed = run(
        &sandbox,
        &wide_limits(),
        "list_directory",
        json!({"path": "."}),
    );
    let FsOutcome::Listed(list) = listed else {
        panic!("list");
    };
    let entry = list
        .entries
        .iter()
        .find(|entry| entry.name == "link")
        .expect("link");
    assert_eq!(entry.kind, "reparse");

    let searched = run(
        &sandbox,
        &wide_limits(),
        "search_files",
        json!({"query": "ModelRuntime", "path": "."}),
    );
    let FsOutcome::Searched(result) = searched else {
        panic!("search");
    };
    assert!(
        result
            .matches
            .iter()
            .all(|hit| !hit.path.contains("secret") && hit.path != "link/hit.txt"),
        "{result:?}"
    );
    drop(guard);
}

#[cfg(windows)]
struct JunctionGuard(PathBuf);

#[cfg(windows)]
impl Drop for JunctionGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.0);
    }
}

#[cfg(windows)]
fn make_junction(link: &Path, target: &Path) -> (JunctionGuard, std::io::Result<()>) {
    let link_arg = link.to_string_lossy().into_owned();
    let target_arg = target.to_string_lossy().into_owned();
    let output = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J", &link_arg, &target_arg])
        .output();
    let guard = JunctionGuard(link.to_path_buf());
    let result = match output {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(std::io::Error::other(
            String::from_utf8_lossy(&output.stderr).to_string(),
        )),
        Err(error) => Err(error),
    };
    (guard, result)
}

#[cfg(windows)]
#[test]
fn file_symlinks_are_not_followed_when_the_process_can_create_them() {
    let workspace = TempDir::new("symlink-ws");
    let outside = TempDir::new("symlink-out");
    write(&outside.path().join("secret.txt"), "SENTINEL_OUTSIDE\n");
    let link = workspace.path().join("secret.txt");
    match std::os::windows::fs::symlink_file(outside.path().join("secret.txt"), &link) {
        Ok(()) => {
            let sandbox = WorkspaceSandbox::new(workspace.path()).expect("sandbox");
            let error = sandbox.resolve("secret.txt").expect_err("symlink");
            assert_eq!(error.kind(), "reparse_denied", "{error:?}");
            assert!(!format!("{error}").contains("SENTINEL_OUTSIDE"));
            assert_eq!(
                std::fs::read_to_string(outside.path().join("secret.txt")).expect("outside"),
                "SENTINEL_OUTSIDE\n"
            );
        }
        Err(error) => {
            let code = error.raw_os_error();
            assert!(
                code == Some(1314) || code == Some(5),
                "symlink creation failed with an unexpected error: {error} ({code:?})"
            );
        }
    }
}

#[cfg(windows)]
#[test]
fn replacing_the_target_between_prepare_and_apply_is_rejected() {
    let root = TempDir::new("swap");
    let outside = TempDir::new("swap-out");
    write(&outside.path().join("secret.txt"), "SENTINEL_OUTSIDE\n");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
    let file = root.path().join("notes.txt");
    write(&file, "alpha\n");
    let FsOutcome::Prepared(prepared) = run(
        &sandbox,
        &wide_limits(),
        "apply_patch",
        json!({"path": "notes.txt", "patch": patch_text("notes.txt", "alpha", "beta")}),
    ) else {
        panic!("prepared");
    };
    std::fs::remove_file(&file).expect("remove");
    write(&file, "alpha\n");
    let grant = ApprovalGrant::issue(&prepared, &prepared.confirmation_line()).expect("grant");
    let error =
        apply_granted(&sandbox, &prepared, grant, &ApprovalLedger::new()).expect_err("identity");
    assert!(
        matches!(error.kind(), "identity_changed" | "conflict"),
        "{error:?}"
    );
    assert_eq!(std::fs::read_to_string(&file).expect("kept"), "alpha\n");
    assert_eq!(
        std::fs::read_to_string(outside.path().join("secret.txt")).expect("outside"),
        "SENTINEL_OUTSIDE\n"
    );
}

#[cfg(windows)]
#[test]
fn an_exclusive_lock_blocks_the_write_without_changing_bytes() {
    use std::os::windows::fs::OpenOptionsExt;
    let root = TempDir::new("lock");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
    let file = root.path().join("notes.txt");
    write(&file, "alpha\n");
    let FsOutcome::Prepared(prepared) = run(
        &sandbox,
        &wide_limits(),
        "apply_patch",
        json!({"path": "notes.txt", "patch": patch_text("notes.txt", "alpha", "beta")}),
    ) else {
        panic!("prepared");
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.share_mode(0);
    let _held = options.open(&file).expect("lock");
    let grant = ApprovalGrant::issue(&prepared, &prepared.confirmation_line()).expect("grant");
    let error =
        apply_granted(&sandbox, &prepared, grant, &ApprovalLedger::new()).expect_err("locked");
    assert!(
        matches!(
            error.kind(),
            "io" | "write_failed" | "conflict" | "identity_changed"
        ),
        "{error:?}"
    );
    drop(_held);
    assert_eq!(
        std::fs::read_to_string(&file).expect("unchanged"),
        "alpha\n"
    );
}

#[test]
fn privacy_policy_hides_and_denies_protected_paths() {
    let root = TempDir::new("privacy");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
    std::fs::create_dir_all(root.path().join("nested").join("src")).expect("nested");
    std::fs::create_dir_all(root.path().join("certs")).expect("certs");
    write(&root.path().join("lca.toml"), "SENTINEL_LCA\n");
    write(&root.path().join("opencode.json"), "SENTINEL_OPEN\n");
    write(&root.path().join(".env"), "SENTINEL_ENV\n");
    write(&root.path().join(".env.local"), "SENTINEL_LOCAL\n");
    write(&root.path().join(".env.example"), "TEMPLATE\n");
    write(&root.path().join("id_rsa"), "SENTINEL_KEY\n");
    write(
        &root.path().join("certs").join("server.pem"),
        "SENTINEL_PEM\n",
    );
    write(&root.path().join("credentials.json"), "SENTINEL_CRED\n");
    write(&root.path().join("secrets.toml"), "SENTINEL_SECRETS\n");
    write(
        &root.path().join("nested").join("src").join("main.rs"),
        "fn main() {}\n",
    );
    write(
        &root.path().join("nested").join("lca.toml"),
        "SENTINEL_NESTED\n",
    );
    write(&root.path().join("Cargo.toml"), "[package]\n");
    write(&root.path().join("keyboard.rs"), "fn key() {}\n");

    for path in [
        "lca.toml",
        "LCA.TOML",
        "./lca.toml",
        "nested/lca.toml",
        "nested\\lca.toml",
        "opencode.json",
        ".env",
        ".env.local",
        "id_rsa",
        "certs/server.pem",
        "credentials.json",
        "secrets.toml",
    ] {
        let error = execute_validated(
            &action("read_file", json!({"path": path})),
            &sandbox,
            &wide_limits(),
        )
        .expect_err(path);
        assert_eq!(error.kind(), "privacy_denied", "{path} -> {error}");
        assert!(!error.to_string().contains("SENTINEL"), "{path}");
    }

    let template = run(
        &sandbox,
        &wide_limits(),
        "read_file",
        json!({"path": ".env.example"}),
    );
    let FsOutcome::Read(template) = template else {
        panic!("template");
    };
    assert_eq!(template.content, "TEMPLATE\n");

    let source = run(
        &sandbox,
        &wide_limits(),
        "read_file",
        json!({"path": "nested/src/main.rs"}),
    );
    let FsOutcome::Read(source) = source else {
        panic!("source");
    };
    assert!(source.content.contains("fn main"));
    let keyboard = run(
        &sandbox,
        &wide_limits(),
        "read_file",
        json!({"path": "keyboard.rs"}),
    );
    assert!(matches!(keyboard, FsOutcome::Read(_)));

    let traversal = execute_validated(
        &action("read_file", json!({"path": "nested/../lca.toml"})),
        &sandbox,
        &wide_limits(),
    )
    .expect_err("traversal");
    assert_eq!(traversal.kind(), "invalid_path");
    assert!(!traversal.to_string().contains("SENTINEL"));

    let listed = run(
        &sandbox,
        &wide_limits(),
        "list_directory",
        json!({"path": "."}),
    );
    let FsOutcome::Listed(listed) = listed else {
        panic!("list");
    };
    let names: Vec<&str> = listed
        .entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    for hidden in [
        "lca.toml",
        "opencode.json",
        ".env",
        ".env.local",
        "id_rsa",
        "credentials.json",
        "secrets.toml",
    ] {
        assert!(!names.contains(&hidden), "{names:?}");
    }
    assert!(names.contains(&"Cargo.toml"));
    assert!(names.contains(&".env.example"));
    assert!(names.contains(&"keyboard.rs"));
    let rendered = format!("{listed:?}");
    assert!(!rendered.contains("suppressed"), "{rendered}");
    assert!(!rendered.contains("SENTINEL"), "{rendered}");

    let searched = run(
        &sandbox,
        &wide_limits(),
        "search_files",
        json!({"query": "SENTINEL", "path": "."}),
    );
    let FsOutcome::Searched(searched) = searched else {
        panic!("search");
    };
    assert!(
        searched.matches.is_empty(),
        "protected hits leaked: {searched:?}"
    );

    let patch = patch_text("lca.toml", "SENTINEL_LCA", "nope");
    let denied = execute_validated(
        &action("apply_patch", json!({"path": "lca.toml", "patch": patch})),
        &sandbox,
        &wide_limits(),
    )
    .expect_err("patch");
    assert_eq!(denied.kind(), "privacy_denied");
    assert_eq!(
        std::fs::read_to_string(root.path().join("lca.toml")).expect("unchanged"),
        "SENTINEL_LCA\n"
    );

    let custom = PrivacyPolicy::try_from_patterns(&["notes/*.secret".to_owned()]).expect("custom");
    let custom_root = TempDir::new("privacy-custom");
    std::fs::create_dir(custom_root.path().join("notes")).expect("notes");
    write(
        &custom_root.path().join("notes").join("local.secret"),
        "SENTINEL_CUSTOM\n",
    );
    write(
        &custom_root.path().join("notes").join("lib.rs"),
        "fn kept() {}\n",
    );
    let custom_sandbox =
        WorkspaceSandbox::with_privacy(custom_root.path(), custom).expect("custom sandbox");
    let blocked = execute_validated(
        &action("read_file", json!({"path": "notes/local.secret"})),
        &custom_sandbox,
        &wide_limits(),
    )
    .expect_err("custom");
    assert_eq!(blocked.kind(), "privacy_denied");
    let kept = run(
        &custom_sandbox,
        &wide_limits(),
        "read_file",
        json!({"path": "notes/lib.rs"}),
    );
    let FsOutcome::Read(kept) = kept else {
        panic!("kept");
    };
    assert!(kept.content.contains("fn kept"));
    assert!(
        PrivacyPolicy::try_from_patterns(&["../secrets".to_owned()]).is_err(),
        "invalid patterns must not be ignored"
    );
}

#[cfg(windows)]
#[test]
fn a_junction_cannot_expose_a_protected_file_or_escape() {
    let workspace = TempDir::new("privacy-junction");
    let outside = TempDir::new("privacy-outside");
    write(&outside.path().join("secret.txt"), "SENTINEL_OUTSIDE\n");
    let link = workspace.path().join("alias");
    let (guard, created) = make_junction(&link, outside.path());
    created.expect("mklink /J");
    let sandbox = WorkspaceSandbox::new(workspace.path()).expect("sandbox");
    let error = execute_validated(
        &action("read_file", json!({"path": "alias/secret.txt"})),
        &sandbox,
        &wide_limits(),
    )
    .expect_err("junction");
    assert_eq!(error.kind(), "reparse_denied", "{error}");
    assert!(!error.to_string().contains("SENTINEL_OUTSIDE"));
    drop(guard);
}

#[cfg(windows)]
#[test]
fn prepare_rejects_a_hardlink_and_does_not_change_either_name() {
    let root = TempDir::new("patch-hardlink");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
    let file = root.path().join("notes.txt");
    let alias = root.path().join("alias.txt");
    write(&file, "alpha\n");
    std::fs::hard_link(&file, &alias).expect("hard link");
    let patch = patch_text("notes.txt", "alpha", "beta");
    let error = execute_validated(
        &action("apply_patch", json!({"path": "notes.txt", "patch": patch})),
        &sandbox,
        &wide_limits(),
    )
    .expect_err("hardlink");
    assert_eq!(error.kind(), "hardlink_denied", "{error}");
    assert_eq!(std::fs::read_to_string(&file).expect("file"), "alpha\n");
    assert_eq!(std::fs::read_to_string(&alias).expect("alias"), "alpha\n");
}

#[test]
fn a_hardlink_alias_of_a_protected_file_is_not_detected() {
    let root = TempDir::new("privacy-hardlink");
    let secret = root.path().join(".env");
    let alias = root.path().join("notes.txt");
    write(&secret, "alias-visible\n");
    std::fs::hard_link(&secret, &alias).expect("hard link");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
    let denied = execute_validated(
        &action("read_file", json!({"path": ".env"})),
        &sandbox,
        &wide_limits(),
    )
    .expect_err("name");
    assert_eq!(denied.kind(), "privacy_denied");
    assert!(!denied.to_string().contains("alias-visible"));
    let read = run(
        &sandbox,
        &wide_limits(),
        "read_file",
        json!({"path": "notes.txt"}),
    );
    let FsOutcome::Read(read) = read else {
        panic!("alias");
    };
    assert_eq!(read.content, "alias-visible\n");
}

#[test]
fn sampled_paths_never_resolve_outside_the_workspace() {
    let root = TempDir::new("prop");
    write(&root.path().join("kept.txt"), "kept\n");
    let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
    let samples = [
        ".",
        "kept.txt",
        "..",
        "../kept.txt",
        "foo/../../kept.txt",
        "C:\\kept.txt",
        "\\\\server\\kept.txt",
        "kept.txt:stream",
        "NUL",
        ".git/config",
        "foo/./kept.txt",
    ];
    for sample in samples {
        match sandbox.resolve(sample) {
            Ok(resolved) => {
                assert!(
                    resolved.absolute().starts_with(sandbox.root()),
                    "{sample} -> {}",
                    resolved.absolute().display()
                );
            }
            Err(error) => {
                assert!(!format!("{error}").contains("kept\n"), "{sample}");
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

    #[test]
    fn arbitrary_paths_do_not_escape(raw in "\\PC{0,48}") {
        let root = TempDir::new("proptest");
        std::fs::write(root.path().join("kept.txt"), "kept\n").expect("seed");
        let sandbox = WorkspaceSandbox::new(root.path()).expect("sandbox");
        if let Ok(resolved) = sandbox.resolve(&raw) {
            prop_assert!(resolved.absolute().starts_with(sandbox.root()));
        }
    }
}
