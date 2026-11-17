//! Failures from the workspace sandbox and the filesystem tools.
//!
//! Messages name the relative path the caller supplied. They do not include file bytes.

use std::path::PathBuf;

/// Filesystem tool or sandbox failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FsError {
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

    /// The caller path failed a static check.
    #[error("{message}")]
    InvalidPath {
        /// Static explanation.
        message: String,
    },

    /// The resolved path is not inside the workspace root.
    #[error("path {path} is outside the workspace")]
    OutsideWorkspace {
        /// Caller path, capped for diagnostics.
        path: String,
    },

    /// A symlink, junction, or other reparse point was encountered.
    #[error("path {path} uses a symlink, junction, or other reparse point")]
    ReparseDenied {
        /// Caller path, capped for diagnostics.
        path: String,
    },

    /// The final path does not exist.
    #[error("path {path} does not exist")]
    NotFound {
        /// Caller path, capped for diagnostics.
        path: String,
    },

    /// A file operation was pointed at a directory.
    #[error("path {path} is not a file")]
    NotAFile {
        /// Caller path, capped for diagnostics.
        path: String,
    },

    /// A directory operation was pointed at a file.
    #[error("path {path} is not a directory")]
    NotADirectory {
        /// Caller path, capped for diagnostics.
        path: String,
    },

    /// The file contains a NUL byte.
    #[error("path {path} is a binary file")]
    BinaryFile {
        /// Caller path, capped for diagnostics.
        path: String,
    },

    /// The file is not UTF-8.
    #[error("path {path} is not valid UTF-8")]
    InvalidUtf8 {
        /// Caller path, capped for diagnostics.
        path: String,
    },

    /// The file is larger than the configured limit.
    #[error("path {path} exceeds {limit} bytes")]
    TooLarge {
        /// Caller path, capped for diagnostics.
        path: String,
        /// Limit in bytes.
        limit: u64,
    },

    /// The file length or identity changed during the read.
    #[error("path {path} changed while it was being read")]
    FileChanged {
        /// Caller path, capped for diagnostics.
        path: String,
    },

    /// The directory entry is no longer the file that was prepared.
    #[error("path {path} no longer refers to the same file")]
    IdentityChanged {
        /// Caller path, capped for diagnostics.
        path: String,
    },

    /// The target has more than one name. A workspace hard link can alias bytes outside the root.
    #[error("path {path} has more than one hard link")]
    HardlinkDenied {
        /// Caller path, capped for diagnostics.
        path: String,
    },

    /// The platform did not provide a file index that can be compared later.
    #[error("path {path} has no usable file identity")]
    UnverifiableIdentity {
        /// Caller path, capped for diagnostics.
        path: String,
    },

    /// The path names `.git` or another protected component.
    #[error("path {path} is inside a protected directory")]
    ProtectedPath {
        /// Caller path, capped for diagnostics.
        path: String,
    },

    /// A privacy rule rejected the path before its contents were read.
    ///
    /// The message does not include the path or any file bytes. The caller already
    /// supplied the path. Listings omit the name instead of returning this error.
    #[error("access to a protected workspace path was denied")]
    PrivacyDenied,

    /// Search was aimed at `target`, `.git`, or `node_modules`.
    #[error("path {path} is excluded from search")]
    ExcludedPath {
        /// Caller path, capped for diagnostics.
        path: String,
    },

    /// Configuration turned the tool class off.
    #[error("tool {tool} is disabled")]
    ToolDisabled {
        /// Tool name.
        tool: String,
    },

    /// The JSON arguments are not the shape the tool accepts.
    #[error("{message}")]
    InvalidArguments {
        /// Static explanation.
        message: String,
    },

    /// The unified diff is not the single-file subset this milestone accepts.
    #[error("patch was rejected: {message}")]
    InvalidPatch {
        /// Static explanation.
        message: String,
    },

    /// A context or removed line does not match the file.
    #[error("patch context does not match: {message}")]
    ContextMismatch {
        /// Line explanation. It does not include the file.
        message: String,
    },

    /// The file or the diff uses a newline layout this milestone refuses.
    #[error("patch layout is not supported: {message}")]
    UnsupportedLayout {
        /// Static explanation.
        message: String,
    },

    /// A write was requested without a trusted confirmation line.
    #[error("write approval is required")]
    ApprovalRequired,

    /// The confirmation line does not match the prepared action.
    #[error("write approval was rejected")]
    ApprovalRejected,

    /// The grant was issued for a different prepared patch.
    #[error("write approval does not match the prepared patch")]
    ApprovalMismatch,

    /// This binding was already used.
    #[error("write approval was already used")]
    ApprovalConsumed,

    /// The file hash changed between prepare and apply.
    #[error("path {path} changed after the patch was prepared")]
    Conflict {
        /// Relative path.
        path: String,
    },

    /// Creating, syncing, or replacing the file failed.
    #[error("path {path} could not be written: {message}")]
    WriteFailed {
        /// Relative path.
        path: String,
        /// Filesystem error text.
        message: String,
    },

    /// The bytes on disk after the replace were not the prepared bytes.
    #[error("path {path} did not match the expected bytes after writing")]
    VerifyFailed {
        /// Relative path.
        path: String,
    },

    /// A test fault point fired. Production calls do not construct this.
    #[error("injected fault {point}")]
    FaultInjected {
        /// Fault point name.
        point: &'static str,
        /// Whether the target bytes may already have changed.
        published: bool,
    },

    /// A filesystem call failed.
    #[error("filesystem error for {path}: {message}")]
    Io {
        /// Relative or caller path.
        path: String,
        /// Filesystem error text.
        message: String,
    },

    /// The tool name is not one the dispatcher runs.
    #[error("tool {name} is not executable")]
    UnsupportedTool {
        /// Tool name, capped.
        name: String,
    },

    /// The in-process approval ledger could not be locked.
    #[error("approval ledger is unavailable")]
    LedgerUnavailable,

    /// The stored proposal is not a valid protected record.
    #[error("patch proposal was rejected: {message}")]
    ProposalInvalid {
        /// Static explanation. It does not include file bytes.
        message: String,
    },

    /// The proposal is past its expiry.
    #[error("patch proposal has expired")]
    ProposalExpired,

    /// A restoration contract, its evidence, or its source state was rejected.
    ///
    /// The message is static. It does not include file bytes.
    #[error("restoration was rejected: {message}")]
    RestorationRejected {
        /// Static explanation.
        message: String,
    },

    /// This platform cannot verify an apply.
    #[error("verified patch apply is not supported on this platform")]
    UnsupportedPlatform,

    /// The proposal belongs to a different workspace identity.
    #[error("patch proposal is bound to a different workspace")]
    WorkspaceMismatch,

    /// The protected proposal store could not be used.
    #[error("proposal store is unavailable: {message}")]
    StoreUnavailable {
        /// Static explanation. It does not include file bytes.
        message: String,
    },

    /// A directory or search exceeded a hard scan cap.
    #[error("{message}")]
    LimitExceeded {
        /// Static explanation.
        message: String,
    },
}

impl FsError {
    /// Stable classification. It does not include paths or file bytes.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::WorkspaceNotFound { .. } => "workspace_not_found",
            Self::WorkspaceNotDirectory { .. } => "workspace_not_directory",
            Self::InvalidWorkspace { .. } => "invalid_workspace",
            Self::InvalidPath { .. } => "invalid_path",
            Self::OutsideWorkspace { .. } => "outside_workspace",
            Self::ReparseDenied { .. } => "reparse_denied",
            Self::NotFound { .. } => "not_found",
            Self::NotAFile { .. } => "not_a_file",
            Self::NotADirectory { .. } => "not_a_directory",
            Self::BinaryFile { .. } => "binary_file",
            Self::InvalidUtf8 { .. } => "invalid_utf8",
            Self::TooLarge { .. } => "too_large",
            Self::FileChanged { .. } => "file_changed",
            Self::IdentityChanged { .. } => "identity_changed",
            Self::HardlinkDenied { .. } => "hardlink_denied",
            Self::UnverifiableIdentity { .. } => "unverifiable_identity",
            Self::ProtectedPath { .. } => "protected_path",
            Self::PrivacyDenied => "privacy_denied",
            Self::ExcludedPath { .. } => "excluded_path",
            Self::ToolDisabled { .. } => "tool_disabled",
            Self::InvalidArguments { .. } => "invalid_arguments",
            Self::InvalidPatch { .. } => "invalid_patch",
            Self::ContextMismatch { .. } => "context_mismatch",
            Self::UnsupportedLayout { .. } => "unsupported_layout",
            Self::ApprovalRequired => "approval_required",
            Self::ApprovalRejected => "approval_rejected",
            Self::ApprovalMismatch => "approval_mismatch",
            Self::ApprovalConsumed => "approval_consumed",
            Self::Conflict { .. } => "conflict",
            Self::WriteFailed { .. } => "write_failed",
            Self::VerifyFailed { .. } => "verify_failed",
            Self::FaultInjected { .. } => "fault_injected",
            Self::Io { .. } => "io",
            Self::UnsupportedTool { .. } => "unsupported_tool",
            Self::LedgerUnavailable => "ledger_unavailable",
            Self::ProposalInvalid { .. } => "proposal_invalid",
            Self::ProposalExpired => "proposal_expired",
            Self::RestorationRejected { .. } => "restoration_rejected",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::WorkspaceMismatch => "workspace_mismatch",
            Self::StoreUnavailable { .. } => "store_unavailable",
            Self::LimitExceeded { .. } => "limit_exceeded",
        }
    }
}

pub(crate) fn display_path(raw: &str) -> String {
    let mut short: String = raw.chars().take(180).collect();
    if raw.chars().count() > 180 {
        short.push_str("...");
    }
    short
}
