//! Tool requests, workspace authorization, and model-proposed action validation.
//!
//! The executor evaluates authorization rules and then refuses to run the tool.
//! [`action`] validates structured tool calls from a model. Neither path reads file
//! contents, modifies the workspace, or starts a process.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod action;

mod auth;
mod error;
mod executor;
mod model;
mod pathutil;

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
pub use model::{ToolArguments, ToolName, ToolRequest, ToolResult};
