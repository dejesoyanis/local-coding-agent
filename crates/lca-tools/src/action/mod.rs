//! Canonical model for tool calls proposed by a model.
//!
//! [`crate::ToolArguments`] is the LCA-01A enum of path, search, and command arguments.
//! [`ToolArguments`] in this module is the JSON value of a model proposal. The two types
//! are not interchangeable. Parsing either one does not authorize an action.
//!
//! [`validate_batch`] is fail-closed. One invalid or denied action rejects the whole batch.
//! The function does not accept a [`crate::ToolExecutor`] and does not execute anything.

/// Largest number of actions accepted from one model response.
///
/// The native transport uses the same limit. A larger batch is rejected as a whole.
pub const MAX_ACTIONS: usize = 8;

mod json_protocol;
mod model;
mod policy;
mod registry;
mod schema;
mod validate;

pub use json_protocol::{
    AGENT_PROTOCOL_VERSION, ActionDocument, JsonProtocolError, MAX_PROTOCOL_BYTES,
    PROTOCOL_VERSION, ParsedAction, parse_action_document, parse_agent_document,
};
pub use model::{
    ActionId, ActionIdFactory, ActionSource, ActionStatus, AgentAction, ToolArguments, ToolCall,
    propose_actions,
};
pub use policy::{PolicyDecision, PolicyDenyReason, authorize_proposal};
pub use registry::{
    MAX_ARGUMENT_BYTES, PermissionCategory, RegisteredTool, RegistryError, ToolEffect, ToolRegistry,
};
pub use validate::{ActionValidationError, ToolCallBatch, ValidatedAction, validate_batch};
