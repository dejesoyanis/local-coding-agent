//! Shared runtime contract.
//!
//! Adapter tests call [`exercise`] with their own [`ModelRuntime`]. The harness uses fixed
//! model identifiers so a later llama.cpp adapter can satisfy the same checks:
//!
//! | Model | Required behavior |
//! | --- | --- |
//! | `contract-ok` | `generate` returns text `hello`, finish reason `stop`, input tokens 3, output tokens 1, and no invented timing |
//! | `contract-missing` | `generate` returns [`RuntimeError::ModelNotFound`] |
//! | `contract-stream` | deltas `Hello` and ` world`, then one completion with finish reason `stop` and no token counts |
//! | `contract-cut` | delta `cut`, then [`RuntimeError::StreamInterrupted`], and no completion |
//! | `contract-hang` | delta `partial`, then no further event until the stream is dropped |
//!
//! An invalid request must return [`RuntimeError::InvalidRequest`] without depending on a backend.

use futures_util::StreamExt;

use crate::error::RuntimeError;
use crate::message::Message;
use crate::request::{GenerationOptions, GenerationRequest};
use crate::response::{FinishReason, GenerationEvent, GenerationMetadata};
use crate::runtime::ModelRuntime;

#[cfg(test)]
use crate::capabilities::{CapabilityParts, CapabilityStatus, ModelCapabilities};
#[cfg(test)]
use crate::response::GenerationResponse;
#[cfg(test)]
use crate::runtime::GenerationStream;

/// Model that completes a non-streaming generation.
pub const MODEL_OK: &str = "contract-ok";

/// Model that is absent.
pub const MODEL_MISSING: &str = "contract-missing";

/// Model that streams two deltas and then completes.
pub const MODEL_STREAM: &str = "contract-stream";

/// Model whose stream ends without a terminal completion.
pub const MODEL_CUT: &str = "contract-cut";

/// Model whose stream yields one delta and then waits until dropped.
pub const MODEL_HANG: &str = "contract-hang";

/// Text returned for [`MODEL_OK`].
pub const OK_TEXT: &str = "hello";

/// Input token count returned for [`MODEL_OK`].
pub const OK_INPUT_TOKENS: u64 = 3;

/// Output token count returned for [`MODEL_OK`].
pub const OK_OUTPUT_TOKENS: u64 = 1;

/// Deltas returned for [`MODEL_STREAM`], in order.
pub const STREAM_PARTS: [&str; 2] = ["Hello", " world"];

/// First delta returned for [`MODEL_CUT`].
pub const CUT_TEXT: &str = "cut";

/// First delta returned for [`MODEL_HANG`].
pub const HANG_TEXT: &str = "partial";

/// Runs the shared contract against `runtime`.
///
/// # Panics
///
/// Panics when `runtime` breaks a contract invariant. This function is a test harness.
pub async fn exercise(runtime: &dyn ModelRuntime) {
    let invalid = match runtime
        .generate(GenerationRequest::contract_invalid())
        .await
    {
        Ok(_) => panic!("invalid request unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_eq!(
        invalid.kind(),
        "invalid_request",
        "invalid requests must fail before a backend result: {invalid}"
    );

    let response = runtime
        .generate(must_request(MODEL_OK))
        .await
        .unwrap_or_else(|error| panic!("contract-ok failed: {error}"));
    assert_eq!(response.model(), MODEL_OK);
    assert_eq!(response.text(), OK_TEXT);
    assert_eq!(response.finish_reason(), Some(&FinishReason::Stop));
    let usage = response
        .usage()
        .unwrap_or_else(|| panic!("contract-ok omitted token counts"));
    assert_eq!(usage.input_tokens, Some(OK_INPUT_TOKENS));
    assert_eq!(usage.output_tokens, Some(OK_OUTPUT_TOKENS));
    assert_eq!(response.timing(), None);

    let missing = match runtime.generate(must_request(MODEL_MISSING)).await {
        Ok(_) => panic!("missing model unexpectedly succeeded"),
        Err(error) => error,
    };
    match missing {
        RuntimeError::ModelNotFound { model, .. } => assert_eq!(model, MODEL_MISSING),
        other => panic!("expected model_not_found, got {other}"),
    }

    let streamed = collect_until_terminal(runtime, MODEL_STREAM).await;
    let ok_events: Vec<GenerationEvent> = streamed
        .into_iter()
        .map(|event| event.unwrap_or_else(|error| panic!("contract-stream failed: {error}")))
        .collect();
    assert!(
        crate::response::successful_stream_shape(&ok_events),
        "contract-stream shape: {ok_events:?}"
    );
    assert_eq!(
        ok_events,
        vec![
            GenerationEvent::TextDelta(STREAM_PARTS[0].to_owned()),
            GenerationEvent::TextDelta(STREAM_PARTS[1].to_owned()),
            GenerationEvent::Completed(GenerationMetadata::new(
                MODEL_STREAM,
                Some(FinishReason::Stop),
                None,
                None,
            )),
        ]
    );

    let cut = collect_until_terminal(runtime, MODEL_CUT).await;
    assert_eq!(cut.len(), 2, "contract-cut events: {cut:?}");
    assert_eq!(
        cut[0].as_ref().ok(),
        Some(&GenerationEvent::TextDelta(CUT_TEXT.to_owned()))
    );
    let interrupted = match cut[1].as_ref() {
        Ok(event) => panic!("contract-cut completed with {event:?}"),
        Err(error) => error,
    };
    assert_eq!(interrupted.kind(), "stream_interrupted", "{interrupted}");

    let mut hanging = runtime
        .generate_stream(must_request(MODEL_HANG))
        .await
        .unwrap_or_else(|error| panic!("contract-hang failed to start: {error}"));
    let first = hanging
        .next()
        .await
        .unwrap_or_else(|| panic!("contract-hang produced no event"));
    match first {
        Ok(GenerationEvent::TextDelta(text)) => assert_eq!(text, HANG_TEXT),
        other => panic!("contract-hang first event was {other:?}"),
    }
    drop(hanging);
}

async fn collect_until_terminal(
    runtime: &dyn ModelRuntime,
    model: &str,
) -> Vec<Result<GenerationEvent, RuntimeError>> {
    let mut stream = runtime
        .generate_stream(must_request(model))
        .await
        .unwrap_or_else(|error| panic!("{model} failed to start: {error}"));
    let mut events = Vec::new();
    while let Some(event) = stream.next().await {
        let stop = event.is_err();
        events.push(event);
        if stop || events.len() > 16 {
            break;
        }
    }
    if matches!(events.last(), Some(Err(_))) {
        assert!(
            stream.next().await.is_none(),
            "{model} emitted another event after an error"
        );
    }
    events
}

/// A request that fails [`GenerationRequest::validate`].
///
/// Adapters must reject it before performing I/O.
#[must_use]
pub fn invalid_request() -> GenerationRequest {
    GenerationRequest::contract_invalid()
}

fn must_request(model: &str) -> GenerationRequest {
    match GenerationRequest::try_new(
        model,
        vec![Message::user("ping")],
        GenerationOptions::default(),
    ) {
        Ok(request) => request,
        Err(error) => panic!("contract request was rejected: {error}"),
    }
}

/// In-memory runtime used to prove the contract harness itself.
#[cfg(test)]
struct ScriptedRuntime;

#[cfg(test)]
#[async_trait::async_trait]
impl ModelRuntime for ScriptedRuntime {
    async fn generate(
        &self,
        request: GenerationRequest,
    ) -> Result<GenerationResponse, RuntimeError> {
        request.validate()?;
        match request.model() {
            MODEL_OK => Ok(GenerationResponse::complete(
                MODEL_OK,
                OK_TEXT,
                Some(FinishReason::Stop),
                crate::response::TokenUsage::from_counts(
                    Some(OK_INPUT_TOKENS),
                    Some(OK_OUTPUT_TOKENS),
                ),
                None,
            )),
            MODEL_MISSING => Err(RuntimeError::model_not_found(MODEL_MISSING, None)),
            other => Err(RuntimeError::backend(
                Some(500),
                format!("unexpected model {other}"),
            )),
        }
    }

    async fn generate_stream(
        &self,
        request: GenerationRequest,
    ) -> Result<GenerationStream, RuntimeError> {
        request.validate()?;
        let events: Vec<Result<GenerationEvent, RuntimeError>> = match request.model() {
            MODEL_STREAM => vec![
                Ok(GenerationEvent::TextDelta(STREAM_PARTS[0].to_owned())),
                Ok(GenerationEvent::TextDelta(STREAM_PARTS[1].to_owned())),
                Ok(GenerationEvent::Completed(GenerationMetadata::new(
                    MODEL_STREAM,
                    Some(FinishReason::Stop),
                    None,
                    None,
                ))),
            ],
            MODEL_CUT => vec![
                Ok(GenerationEvent::TextDelta(CUT_TEXT.to_owned())),
                Err(RuntimeError::stream_interrupted(None)),
            ],
            MODEL_HANG => {
                let head = futures_util::stream::once(async {
                    Ok(GenerationEvent::TextDelta(HANG_TEXT.to_owned()))
                });
                let tail = futures_util::stream::once(async {
                    std::future::pending::<Result<GenerationEvent, RuntimeError>>().await
                });
                return Ok(GenerationStream::from_stream(head.chain(tail)));
            }
            other => {
                return Err(RuntimeError::backend(
                    Some(500),
                    format!("unexpected model {other}"),
                ));
            }
        };
        Ok(GenerationStream::from_stream(futures_util::stream::iter(
            events,
        )))
    }

    async fn capabilities(&self, model: &str) -> Result<ModelCapabilities, RuntimeError> {
        if model.is_empty() {
            return Err(RuntimeError::invalid("model name must not be empty"));
        }
        Ok(ModelCapabilities::from_parts(
            model,
            CapabilityParts {
                chat: CapabilityStatus::Unknown,
                ..CapabilityParts::default()
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scripted_runtime_satisfies_the_contract() {
        let exercise = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            exercise(&ScriptedRuntime),
        )
        .await;
        assert!(exercise.is_ok(), "contract exercise timed out");
    }
}
