//! Dispatch of a validated action.
//!
//! [`dispatch_validated`] runs read tools and prepares a patch. It has no approval
//! parameter, so it cannot write. [`commit_prepared`] writes only when the confirmation
//! is a [`WriteConfirmation::TrustedCliLine`] for that prepared action.

use lca_tools::{
    ApplyResult, ApprovalGrant, ApprovalLedger, FsError, FsLimits, FsOutcome, PreparedPatch,
    ValidatedAction, WorkspaceSandbox, apply_granted, execute_validated,
};

/// Confirmation from the process that displayed a prepared diff.
///
/// Model arguments are not a variant of this enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteConfirmation {
    /// The caller did not grant the write.
    Absent,
    /// One line read from the local CLI after the preview was shown.
    TrustedCliLine(String),
}

/// Runs a validated action without writing.
pub fn dispatch_validated(
    action: &ValidatedAction,
    sandbox: &WorkspaceSandbox,
    limits: &FsLimits,
) -> Result<FsOutcome, FsError> {
    execute_validated(action, sandbox, limits)
}

/// Applies a prepared patch when the trusted line matches that action.
pub fn commit_prepared(
    sandbox: &WorkspaceSandbox,
    prepared: &PreparedPatch,
    confirmation: WriteConfirmation,
    ledger: &ApprovalLedger,
) -> Result<ApplyResult, FsError> {
    let WriteConfirmation::TrustedCliLine(line) = confirmation else {
        return Err(FsError::ApprovalRequired);
    };
    let grant = ApprovalGrant::issue(prepared, &line)?;
    apply_granted(sandbox, prepared, grant, ledger)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lca_tools::{ActionIdFactory, ActionSource, ToolRegistry, propose_actions, validate_batch};
    use serde_json::json;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!("lca-core-dispatch-{nanos}"));
            std::fs::create_dir_all(&path).expect("temp");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn absent_confirmation_does_not_write() {
        let root = TempDir::new();
        let file = root.0.join("notes.txt");
        std::fs::write(&file, "alpha\n").expect("seed");
        let sandbox = WorkspaceSandbox::new(&root.0).expect("sandbox");
        let registry = ToolRegistry::workspace().expect("registry");
        let patch = "--- a/notes.txt\n+++ b/notes.txt\n@@ -1,1 +1,1 @@\n-alpha\n+beta\n";
        let proposed = propose_actions(
            &ActionIdFactory::new(),
            ActionSource::Native,
            [(
                "apply_patch".to_owned(),
                json!({"path": "notes.txt", "patch": patch}),
            )],
        );
        let batch = validate_batch(&registry, &proposed).expect("batch");
        let outcome = dispatch_validated(&batch.actions()[0], &sandbox, &FsLimits::conservative())
            .expect("prepare");
        let FsOutcome::Prepared(prepared) = outcome else {
            panic!("prepared");
        };
        let error = commit_prepared(
            &sandbox,
            &prepared,
            WriteConfirmation::Absent,
            &ApprovalLedger::new(),
        )
        .expect_err("absent");
        assert_eq!(error.kind(), "approval_required");
        assert_eq!(
            std::fs::read_to_string(&file).expect("unchanged"),
            "alpha\n"
        );

        let model = commit_prepared(
            &sandbox,
            &prepared,
            WriteConfirmation::TrustedCliLine("approve".to_owned()),
            &ApprovalLedger::new(),
        )
        .expect_err("model");
        assert_eq!(model.kind(), "approval_rejected");
        assert_eq!(std::fs::read_to_string(&file).expect("still"), "alpha\n");
    }
}
