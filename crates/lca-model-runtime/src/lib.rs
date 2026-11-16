//! Backend-neutral contracts for local model inference.
//!
//! The agent core and the command-line composition root talk to [`ModelRuntime`].
//! Concrete adapters, including Ollama and a future llama.cpp backend, depend on this
//! crate. This crate does not depend on an HTTP stack, a model file format, or a cloud API.
//!
//! Tool messages and multimodal content are not part of this contract. Native tool-call
//! transport is: a request may advertise tool definitions, and a completed response may carry
//! raw tool calls. This crate does not validate those calls against a registry and does not
//! execute them. Streaming remains text-only.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod capabilities;
mod error;
mod message;
mod protocol;
mod request;
mod response;
mod runtime;
mod tool;

#[cfg(any(test, feature = "contract"))]
pub mod contract;

pub use capabilities::{CapabilityParts, CapabilityStatus, ModelCapabilities};
pub use error::{RuntimeError, report};
pub use message::{Message, MessageRole};
pub use protocol::{
    ProtocolAvailability, ProtocolPreference, ProtocolSelectionError, SelectedProtocol,
    select_protocol,
};
pub use request::{
    GenerationOptions, GenerationRequest, MAX_CONTEXT_TOKENS, MAX_MESSAGE_CHARS, MAX_MESSAGES,
    MAX_MODEL_NAME_LEN, MAX_TIMEOUT, SamplingParams,
};
pub use response::{
    FinishReason, GenerationEvent, GenerationMetadata, GenerationResponse, TimingMetadata,
    TokenUsage,
};
pub use runtime::{GenerationStream, ModelRuntime};
pub use tool::{
    MAX_NATIVE_TOOL_CALLS, MAX_TOOL_DESCRIPTION_LEN, MAX_TOOL_NAME_LEN, MAX_TOOLS_PER_REQUEST,
    RawToolCall, ResponseFormat, ToolDefinition,
};
