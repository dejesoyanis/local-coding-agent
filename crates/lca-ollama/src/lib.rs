//! Minimal client for the local Ollama HTTP API.
//!
//! This milestone only checks that the server is reachable and that a model is advertised.
//! It does not generate text and it does not implement tool calling. Unit tests use an
//! in-process TCP stub or no network at all; they do not require Ollama to be running.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod client;
mod dto;
mod error;

pub use client::{HttpOllamaClient, OllamaClient};
pub use dto::{RemoteModel, TagsResponse, VersionResponse, model_is_present, names_match};
pub use error::{OllamaAvailability, OllamaError};
