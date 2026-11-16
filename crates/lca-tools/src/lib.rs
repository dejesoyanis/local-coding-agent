//! Tool requests, workspace authorization, and model-proposed action validation.
//!
//! [`action`] validates structured tool calls and does not execute them.
//! [`executor`] still refuses the LCA-01A tool requests. [`fs`] runs the filesystem
//! tools after that validation, inside [`sandbox`]. `apply_patch` prepares bytes in
//! memory; only [`fs::apply_granted`] writes, and only with an approval grant.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod action;
pub mod fs;
pub mod sandbox;

mod auth;
mod error;
mod executor;
mod fs_error;
mod model;
mod pathutil;
mod privacy;

pub use action::{
    ActionId, ActionIdFactory, ActionSource, ActionStatus, ActionValidationError, AgentAction,
    JsonProtocolError, MAX_ACTIONS, MAX_ARGUMENT_BYTES, MAX_PROTOCOL_BYTES, PROTOCOL_VERSION,
    ParsedAction, PermissionCategory, PolicyDecision, PolicyDenyReason, RegisteredTool,
    RegistryError, ToolCall, ToolCallBatch, ToolEffect, ToolRegistry, ValidatedAction,
    authorize_proposal, parse_action_document, propose_actions, validate_batch,
};
pub use auth::{AuthorizationDecision, ToolAuthorization, WorkspaceScope};
pub use error::{DenyReason, ToolError};
pub use executor::{RejectingToolExecutor, ToolExecutor};
pub use fs::{
    ApplyResult, ApprovalGrant, ApprovalLedger, DirectoryEntry, FsLimitValues, FsLimits, FsOutcome,
    ListResult, PreparedPatch, ReadResult, SearchMatch, SearchResult, apply_granted,
    execute_validated,
};
pub use fs_error::FsError;
pub use model::{ToolArguments, ToolName, ToolRequest, ToolResult};
pub use privacy::{PrivacyPatternError, PrivacyPolicy, deny_overrides};
pub use sandbox::{ResolvedKind, ResolvedPath, WorkspaceSandbox};
