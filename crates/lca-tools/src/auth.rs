use std::path::{Path, PathBuf};

use crate::error::DenyReason;
use crate::model::{ToolArguments, ToolName, ToolRequest, arguments_match};
use crate::pathutil::{is_within, normalize_lexical, simplify_verbatim};

const MAX_SEARCH_CHARS: usize = 1024;
const MAX_COMMAND_CHARS: usize = 4096;

/// Decision recorded for one request against one workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    /// The request stays inside the workspace. Execution is still a separate step.
    InWorkspace {
        /// Canonical path that would have been used.
        path: PathBuf,
    },
    /// The request must not proceed.
    Denied(DenyReason),
}

impl AuthorizationDecision {
    /// Stable classification for diagnostics.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::InWorkspace { .. } => "in_workspace",
            Self::Denied(reason) => reason.kind(),
        }
    }
}

/// Authorization result, including the workspace it was judged against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolAuthorization {
    tool: ToolName,
    workspace_root: PathBuf,
    decision: AuthorizationDecision,
}

impl ToolAuthorization {
    /// Tool that was judged.
    #[must_use]
    pub const fn tool(&self) -> ToolName {
        self.tool
    }

    /// Canonical workspace root.
    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// Allow or deny decision.
    #[must_use]
    pub const fn decision(&self) -> &AuthorizationDecision {
        &self.decision
    }
}

/// Canonical workspace used to confine every path-bearing tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceScope {
    root: PathBuf,
}

impl WorkspaceScope {
    /// Accepts an existing directory and stores its canonical path.
    pub fn new(root: &Path) -> Result<Self, crate::error::ToolError> {
        let metadata = match std::fs::metadata(root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(crate::error::ToolError::WorkspaceNotFound {
                    path: root.to_path_buf(),
                });
            }
            Err(error) => {
                return Err(crate::error::ToolError::InvalidWorkspace {
                    path: root.to_path_buf(),
                    message: error.to_string(),
                });
            }
        };
        if !metadata.is_dir() {
            return Err(crate::error::ToolError::WorkspaceNotDirectory {
                path: root.to_path_buf(),
            });
        }

        let canonical = std::fs::canonicalize(root).map_err(|error| {
            crate::error::ToolError::InvalidWorkspace {
                path: root.to_path_buf(),
                message: error.to_string(),
            }
        })?;
        let root = simplify_verbatim(canonical);
        if !root.is_dir() {
            return Err(crate::error::ToolError::WorkspaceNotDirectory { path: root });
        }
        Ok(Self { root })
    }

    /// Canonical workspace root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Judges `request` without reading file contents or starting a process.
    #[must_use]
    pub fn authorize(&self, request: &ToolRequest) -> ToolAuthorization {
        let decision = self.decide(request);
        tracing::debug!(
            tool = request.name().as_str(),
            decision = decision.kind(),
            "judged tool authorization"
        );
        ToolAuthorization {
            tool: request.name(),
            workspace_root: self.root.clone(),
            decision,
        }
    }

    fn decide(&self, request: &ToolRequest) -> AuthorizationDecision {
        if !arguments_match(request.name(), request.arguments()) {
            return AuthorizationDecision::Denied(DenyReason::InvalidArguments {
                message: "tool arguments do not match the tool".to_owned(),
            });
        }

        match request.arguments() {
            ToolArguments::Path { path } => self.decide_path(request.name(), path),
            ToolArguments::Search { query } => self.decide_search(query),
            ToolArguments::Command { command } => self.decide_command(command),
        }
    }

    fn decide_path(&self, tool: ToolName, path: &Path) -> AuthorizationDecision {
        if path.as_os_str().is_empty() {
            return AuthorizationDecision::Denied(DenyReason::InvalidArguments {
                message: "path must not be empty".to_owned(),
            });
        }

        match self.resolve_inside(path) {
            Ok(_) if tool.is_mutating() => {
                AuthorizationDecision::Denied(DenyReason::MutatingToolDisabled)
            }
            Ok(resolved) => AuthorizationDecision::InWorkspace { path: resolved },
            Err(reason) => AuthorizationDecision::Denied(reason),
        }
    }

    fn decide_search(&self, query: &str) -> AuthorizationDecision {
        if query.is_empty() {
            return AuthorizationDecision::Denied(DenyReason::InvalidArguments {
                message: "search query must not be empty".to_owned(),
            });
        }
        if query.chars().count() > MAX_SEARCH_CHARS {
            return AuthorizationDecision::Denied(DenyReason::InvalidArguments {
                message: "search query is too long".to_owned(),
            });
        }
        AuthorizationDecision::InWorkspace {
            path: self.root.clone(),
        }
    }

    fn decide_command(&self, command: &str) -> AuthorizationDecision {
        if command.chars().count() > MAX_COMMAND_CHARS {
            return AuthorizationDecision::Denied(DenyReason::InvalidArguments {
                message: "command exceeds 4096 characters".to_owned(),
            });
        }
        AuthorizationDecision::Denied(DenyReason::MutatingToolDisabled)
    }

    fn resolve_inside(&self, input: &Path) -> Result<PathBuf, DenyReason> {
        let absolute = if input.is_absolute() {
            input.to_path_buf()
        } else {
            self.root.join(input)
        };
        let lexical = normalize_lexical(&simplify_verbatim(absolute));
        if !is_within(&self.root, &lexical) {
            return Err(DenyReason::OutsideWorkspace {
                path: input.to_path_buf(),
            });
        }

        match canonicalize_existing_prefix(&lexical) {
            Ok(resolved) if is_within(&self.root, &resolved) => Ok(resolved),
            Ok(_) => Err(DenyReason::OutsideWorkspace {
                path: input.to_path_buf(),
            }),
            Err(message) => Err(DenyReason::UnresolvablePath {
                path: input.to_path_buf(),
                message,
            }),
        }
    }
}

fn canonicalize_existing_prefix(path: &Path) -> Result<PathBuf, String> {
    let mut existing = path.to_path_buf();
    let mut missing = Vec::new();

    for _ in 0..256 {
        match existing.try_exists() {
            Ok(true) => {
                let mut resolved = simplify_verbatim(
                    std::fs::canonicalize(&existing).map_err(|error| error.to_string())?,
                );
                for name in missing.iter().rev() {
                    resolved.push(name);
                }
                return Ok(normalize_lexical(&resolved));
            }
            Ok(false) => {
                let Some(name) = existing.file_name().map(std::ffi::OsStr::to_os_string) else {
                    return Ok(normalize_lexical(path));
                };
                missing.push(name);
                if !existing.pop() {
                    return Ok(normalize_lexical(path));
                }
            }
            Err(error) => return Err(error.to_string()),
        }
    }

    Err("path is too deep to resolve".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ToolError;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

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
                "lca-tools-{label}-{}-{nanos}-{id}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
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

    #[test]
    fn rejects_a_missing_or_non_directory_root() {
        let root = TempDir::new("scope");
        let missing = root.path().join("missing");
        assert!(matches!(
            WorkspaceScope::new(&missing).expect_err("missing"),
            ToolError::WorkspaceNotFound { .. }
        ));

        let file = root.path().join("file");
        std::fs::write(&file, "x").expect("file");
        assert!(matches!(
            WorkspaceScope::new(&file).expect_err("file"),
            ToolError::WorkspaceNotDirectory { .. }
        ));
    }

    #[test]
    fn confines_paths_to_the_workspace() {
        let parent = TempDir::new("confine");
        let workspace = parent.path().join("ws");
        let sibling = parent.path().join("ws-evil");
        std::fs::create_dir(&workspace).expect("workspace");
        std::fs::create_dir(&sibling).expect("sibling");
        let scope = WorkspaceScope::new(&workspace).expect("scope");

        let inside = scope.authorize(&ToolRequest::read_file(PathBuf::from("src/main.rs")));
        assert!(
            matches!(inside.decision(), AuthorizationDecision::InWorkspace { .. }),
            "{inside:?}"
        );

        let listed = scope.authorize(&ToolRequest::list_directory(PathBuf::from(".")));
        assert!(matches!(
            listed.decision(),
            AuthorizationDecision::InWorkspace { .. }
        ));

        let sibling_file = sibling.join("secret.txt");
        let outside = scope.authorize(&ToolRequest::read_file(sibling_file));
        assert!(matches!(
            outside.decision(),
            AuthorizationDecision::Denied(DenyReason::OutsideWorkspace { .. })
        ));

        let escaped = scope.authorize(&ToolRequest::read_file(
            workspace.join("..").join("ws-evil").join("secret.txt"),
        ));
        assert!(matches!(
            escaped.decision(),
            AuthorizationDecision::Denied(DenyReason::OutsideWorkspace { .. })
        ));

        let parent_dir = scope.authorize(&ToolRequest::list_directory(PathBuf::from("..")));
        assert!(matches!(
            parent_dir.decision(),
            AuthorizationDecision::Denied(DenyReason::OutsideWorkspace { .. })
        ));

        let empty = scope.authorize(&ToolRequest::read_file(PathBuf::new()));
        assert!(matches!(
            empty.decision(),
            AuthorizationDecision::Denied(DenyReason::InvalidArguments { .. })
        ));
    }

    #[test]
    fn mutating_tools_inside_the_workspace_are_disabled() {
        let root = TempDir::new("mutate");
        let scope = WorkspaceScope::new(root.path()).expect("scope");
        let write = scope.authorize(&ToolRequest::write_file(PathBuf::from("notes.txt")));
        assert_eq!(
            write.decision(),
            &AuthorizationDecision::Denied(DenyReason::MutatingToolDisabled)
        );
        let edit = scope.authorize(&ToolRequest::edit_file(root.path().join("notes.txt")));
        assert_eq!(
            edit.decision(),
            &AuthorizationDecision::Denied(DenyReason::MutatingToolDisabled)
        );
    }

    #[test]
    fn search_and_commands_follow_their_rules() {
        let root = TempDir::new("search");
        let scope = WorkspaceScope::new(root.path()).expect("scope");
        let search = scope.authorize(&ToolRequest::search("main"));
        assert!(matches!(
            search.decision(),
            AuthorizationDecision::InWorkspace { .. }
        ));
        let empty = scope.authorize(&ToolRequest::search("   "));
        assert!(matches!(
            empty.decision(),
            AuthorizationDecision::Denied(DenyReason::InvalidArguments { .. })
        ));

        let command = scope.authorize(&ToolRequest::execute_command("SENTINEL_COMMAND_DO_NOT_RUN"));
        assert_eq!(
            command.decision(),
            &AuthorizationDecision::Denied(DenyReason::MutatingToolDisabled)
        );
        let rendered = format!("{command:?}");
        assert!(!rendered.contains("SENTINEL_COMMAND_DO_NOT_RUN"));
    }

    #[cfg(windows)]
    #[test]
    fn junction_pointing_outside_is_denied() {
        let workspace = TempDir::new("junction-ws");
        let outside = TempDir::new("junction-out");
        let marker = outside.path().join("marker.txt");
        std::fs::write(&marker, "keep").expect("marker");
        let link = workspace.path().join("link");
        let link_arg = link.to_string_lossy().into_owned();
        let outside_arg = outside.path().to_string_lossy().into_owned();
        let output = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J", &link_arg, &outside_arg])
            .output()
            .expect("mklink");
        assert!(
            output.status.success(),
            "mklink failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _junction = JunctionGuard(link.clone());

        let scope = WorkspaceScope::new(workspace.path()).expect("scope");
        let decision = scope.authorize(&ToolRequest::read_file(link.join("marker.txt")));
        assert!(
            matches!(
                decision.decision(),
                AuthorizationDecision::Denied(DenyReason::OutsideWorkspace { .. })
            ),
            "{decision:?}"
        );
        assert_eq!(std::fs::read_to_string(&marker).expect("marker"), "keep");
    }

    #[cfg(windows)]
    struct JunctionGuard(PathBuf);

    #[cfg(windows)]
    impl Drop for JunctionGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(&self.0);
        }
    }
}
