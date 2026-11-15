use crate::WorkspaceScope;
use crate::auth::AuthorizationDecision;
use crate::error::ToolError;
use crate::model::{ToolRequest, ToolResult};

/// Runs an authorized tool. This milestone's implementation has no success path.
pub trait ToolExecutor {
    /// Authorize `request` and refuse to perform it.
    fn execute(&self, request: &ToolRequest) -> Result<ToolResult, ToolError>;
}

/// Executor that authorizes a request and then returns an error.
///
/// Read-shaped requests that stay inside the workspace return [`ToolError::NotImplemented`].
/// Everything else returns [`ToolError::Unauthorized`]. No file is opened and no process starts.
#[derive(Debug, Clone)]
pub struct RejectingToolExecutor {
    scope: WorkspaceScope,
}

impl RejectingToolExecutor {
    /// Confines later judgments to `root`.
    pub fn new(root: &std::path::Path) -> Result<Self, ToolError> {
        Ok(Self {
            scope: WorkspaceScope::new(root)?,
        })
    }

    /// Workspace used for authorization.
    #[must_use]
    pub const fn scope(&self) -> &WorkspaceScope {
        &self.scope
    }
}

impl ToolExecutor for RejectingToolExecutor {
    fn execute(&self, request: &ToolRequest) -> Result<ToolResult, ToolError> {
        let authorization = self.scope.authorize(request);
        match authorization.decision() {
            AuthorizationDecision::Denied(reason) => Err(ToolError::Unauthorized {
                tool: request.name(),
                reason: reason.clone(),
            }),
            AuthorizationDecision::InWorkspace { .. } => Err(ToolError::NotImplemented {
                tool: request.name(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DenyReason;
    use crate::model::ToolName;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path =
                std::env::temp_dir().join(format!("lca-exec-{}-{nanos}-{id}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn execution_never_reads_or_writes_workspace_files() {
        let root = TempDir::new();
        let file = root.0.join("notes.txt");
        std::fs::write(&file, "SENTINEL_DO_NOT_LEAK").expect("seed");
        let executor = RejectingToolExecutor::new(&root.0).expect("executor");

        let read = executor
            .execute(&ToolRequest::read_file(file.clone()))
            .expect_err("read");
        assert_eq!(
            read,
            ToolError::NotImplemented {
                tool: ToolName::ReadFile
            }
        );
        assert!(!format!("{read:?}").contains("SENTINEL_DO_NOT_LEAK"));

        let write = executor
            .execute(&ToolRequest::write_file(file.clone()))
            .expect_err("write");
        assert_eq!(
            write,
            ToolError::Unauthorized {
                tool: ToolName::WriteFile,
                reason: DenyReason::MutatingToolDisabled,
            }
        );
        assert_eq!(
            std::fs::read_to_string(&file).expect("unchanged"),
            "SENTINEL_DO_NOT_LEAK"
        );

        let command = executor
            .execute(&ToolRequest::execute_command("SENTINEL_COMMAND_DO_NOT_RUN"))
            .expect_err("command");
        let rendered = format!("{command} {command:?}");
        assert!(!rendered.contains("SENTINEL_COMMAND_DO_NOT_RUN"));
        assert!(matches!(
            command,
            ToolError::Unauthorized {
                tool: ToolName::ExecuteCommand,
                reason: DenyReason::MutatingToolDisabled,
            }
        ));
    }

    #[test]
    fn every_in_workspace_read_is_still_not_implemented() {
        let root = TempDir::new();
        let executor = RejectingToolExecutor::new(&root.0).expect("executor");
        let requests = [
            ToolRequest::read_file(PathBuf::from("src/lib.rs")),
            ToolRequest::list_directory(PathBuf::from(".")),
            ToolRequest::search("lifecycle"),
        ];
        for request in &requests {
            let error = executor.execute(request).expect_err("refused");
            assert!(
                matches!(error, ToolError::NotImplemented { .. }),
                "{error:?}"
            );
        }
        let result = ToolResult::new(ToolName::ReadFile, "not produced by the executor");
        assert_eq!(result.tool(), ToolName::ReadFile);
        assert!(!executor.execute(&requests[0]).is_ok());
    }
}
