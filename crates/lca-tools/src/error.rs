use std::path::PathBuf;

use crate::model::ToolName;

/// Why a tool request was not authorized.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DenyReason {
    /// Writes, edits, and process execution are disabled in this milestone.
    #[error("filesystem mutation and process execution are disabled")]
    MutatingToolDisabled,

    /// The path is not inside the canonical workspace root.
    #[error("path {path} is outside the workspace")]
    OutsideWorkspace {
        /// Path supplied by the caller.
        path: PathBuf,
    },

    /// The arguments do not match the tool or fail a static check.
    #[error("{message}")]
    InvalidArguments {
        /// Static explanation. It does not repeat command text.
        message: String,
    },

    /// A filesystem lookup failed while resolving a path.
    #[error("path {path} cannot be resolved: {message}")]
    UnresolvablePath {
        /// Path supplied by the caller.
        path: PathBuf,
        /// Filesystem error text.
        message: String,
    },
}

impl DenyReason {
    /// Stable classification that does not include paths or command text.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::MutatingToolDisabled => "mutating_tool_disabled",
            Self::OutsideWorkspace { .. } => "outside_workspace",
            Self::InvalidArguments { .. } => "invalid_arguments",
            Self::UnresolvablePath { .. } => "unresolvable_path",
        }
    }
}

/// Failure while authorizing or refusing a tool.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ToolError {
    /// The workspace root does not exist.
    #[error("workspace root {path} does not exist")]
    WorkspaceNotFound {
        /// Path that was requested.
        path: PathBuf,
    },

    /// The workspace root is not a directory.
    #[error("workspace root {path} is not a directory")]
    WorkspaceNotDirectory {
        /// Path that was requested.
        path: PathBuf,
    },

    /// The workspace root could not be canonicalized.
    #[error("workspace root {path} cannot be canonicalized: {message}")]
    InvalidWorkspace {
        /// Path that was requested.
        path: PathBuf,
        /// Filesystem error text.
        message: String,
    },

    /// The tool name and arguments do not belong together.
    #[error("{message}")]
    InvalidRequest {
        /// Static explanation.
        message: String,
    },

    /// Authorization denied the request.
    #[error("tool {tool} is not authorized: {reason}")]
    Unauthorized {
        /// Tool that was denied.
        tool: ToolName,
        /// Denial reason.
        reason: DenyReason,
    },

    /// The request was inside the workspace and still must not run in this milestone.
    #[error("tool {tool} is not implemented")]
    NotImplemented {
        /// Tool that was refused.
        tool: ToolName,
    },
}
