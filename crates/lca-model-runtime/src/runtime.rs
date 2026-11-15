use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures_util::Stream;

use crate::capabilities::ModelCapabilities;
use crate::error::RuntimeError;
use crate::request::GenerationRequest;
use crate::response::{GenerationEvent, GenerationResponse};

/// Incremental generation.
///
/// Dropping the stream cancels the underlying operation. Adapters must release the request
/// when the stream is dropped and must not emit [`GenerationEvent::Completed`] afterwards.
pub struct GenerationStream {
    inner: Pin<Box<dyn Stream<Item = Result<GenerationEvent, RuntimeError>> + Send>>,
}

impl GenerationStream {
    /// Wraps a stream of generation events.
    #[must_use]
    pub fn from_stream<S>(stream: S) -> Self
    where
        S: Stream<Item = Result<GenerationEvent, RuntimeError>> + Send + 'static,
    {
        Self {
            inner: Box::pin(stream),
        }
    }
}

impl Stream for GenerationStream {
    type Item = Result<GenerationEvent, RuntimeError>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().inner.as_mut().poll_next(context)
    }
}

impl fmt::Debug for GenerationStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenerationStream { .. }")
    }
}

/// Backend-neutral asynchronous model runtime.
///
/// Implementations must validate `request` before performing I/O, must not retry a generation
/// after a transport failure, and must not invent capability or usage data.
#[async_trait]
pub trait ModelRuntime: Send + Sync {
    /// Generates one complete response.
    async fn generate(
        &self,
        request: GenerationRequest,
    ) -> Result<GenerationResponse, RuntimeError>;

    /// Streams incremental text and exactly one terminal completion on success.
    ///
    /// A transport failure or a missing terminal frame is an error. It is not a completion.
    async fn generate_stream(
        &self,
        request: GenerationRequest,
    ) -> Result<GenerationStream, RuntimeError>;

    /// Reports the capabilities the backend explicitly exposes for `model`.
    async fn capabilities(&self, model: &str) -> Result<ModelCapabilities, RuntimeError>;
}
