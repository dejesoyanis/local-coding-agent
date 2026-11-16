//! Local Ollama adapter.
//!
//! [`HttpOllamaClient`] is the LCA-01A health check. It calls `/api/version` and `/api/tags`
//! and does not generate text. [`OllamaModelRuntime`] is the generation adapter: it implements
//! the backend-neutral [`lca_model_runtime::ModelRuntime`] contract with chat, streaming, and
//! capability lookup. The adapter can transport native tool calls. It does not validate them
//! against a registry, execute them, or download models.
//!
//! Unit and integration tests use an in-process HTTP stub or no network at all. They do not
//! require Ollama to be running. The ignored smoke test is the only optional live call.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod client;
mod dto;
mod endpoint;
mod error;
mod map;
mod ndjson;
mod runtime;

pub use client::{HttpOllamaClient, OllamaClient};
pub use dto::{RemoteModel, TagsResponse, VersionResponse, model_is_present, names_match};
pub use error::{OllamaAvailability, OllamaError};
pub use ndjson::MAX_STREAM_FRAME_BYTES;
pub use runtime::{OllamaModelRuntime, OllamaRuntimeConfig};
