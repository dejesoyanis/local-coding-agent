use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::Stream;
use futures_util::StreamExt;
use lca_model_runtime::{
    GenerationRequest, GenerationResponse, GenerationStream, ModelCapabilities, ModelRuntime,
    RuntimeError,
};
use reqwest::redirect::Policy;

use crate::endpoint::{check_loopback_endpoint, check_timeouts};
use crate::map::{capabilities_from_show, chat_payload, error_from_http, response_from_chat_json};
use crate::ndjson::{MAX_STREAM_FRAME_BYTES, events_from_chunks};

const MAX_ERROR_BODY: usize = 8 * 1024;
const MAX_SUCCESS_BODY: usize = 8 * 1024 * 1024;

/// Settings for [`OllamaModelRuntime`].
///
/// The endpoint must be a loopback origin. Generation requests are not retried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OllamaRuntimeConfig {
    endpoint: String,
    connect_timeout: Duration,
    request_timeout: Duration,
}

impl OllamaRuntimeConfig {
    /// Stores the endpoint and timeouts. [`OllamaModelRuntime::connect`] validates them.
    #[must_use]
    pub fn new(
        endpoint: impl Into<String>,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            connect_timeout,
            request_timeout,
        }
    }

    /// Configured origin before normalization.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// TCP connect deadline.
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Default deadline for one generation or capability request.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }
}

/// HTTP adapter for a local Ollama server.
///
/// The client is reused across requests. Redirects and proxies are disabled, and generation
/// is not retried: after a dropped connection it is not known whether Ollama started sampling.
#[derive(Clone)]
pub struct OllamaModelRuntime {
    endpoint: String,
    client: reqwest::Client,
    request_timeout: Duration,
    max_frame: usize,
}

impl std::fmt::Debug for OllamaModelRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OllamaModelRuntime")
            .field("endpoint", &self.endpoint)
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

impl OllamaModelRuntime {
    /// Builds a runtime for a loopback Ollama origin.
    ///
    /// Construction does not open a connection.
    pub fn connect(config: OllamaRuntimeConfig) -> Result<Self, RuntimeError> {
        let endpoint = check_loopback_endpoint(&config.endpoint)?;
        check_timeouts(config.connect_timeout, config.request_timeout)?;
        let client = reqwest::Client::builder()
            .connect_timeout(config.connect_timeout)
            .redirect(Policy::none())
            .no_proxy()
            .user_agent("lca/0.1")
            .tcp_nodelay(true)
            .http1_only()
            .build()
            .map_err(|error| RuntimeError::connection(endpoint.origin.clone(), error))?;
        Ok(Self {
            endpoint: endpoint.origin,
            client,
            request_timeout: config.request_timeout,
            max_frame: MAX_STREAM_FRAME_BYTES,
        })
    }

    /// Normalized loopback origin.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn send_chat(
        &self,
        request: &GenerationRequest,
        stream: bool,
    ) -> Result<reqwest::Response, RuntimeError> {
        let timeout = request.timeout().unwrap_or(self.request_timeout);
        let payload = chat_payload(request, stream)?;
        let url = format!("{}/api/chat", self.endpoint);
        let accept = if stream {
            "application/x-ndjson"
        } else {
            "application/json"
        };
        // One attempt. A retry could duplicate a generation that the server already started.
        let response = self
            .client
            .post(&url)
            .timeout(timeout)
            .header("accept", accept)
            .json(&payload)
            .send()
            .await
            .map_err(|error| map_transport(error, timeout, &self.endpoint))?;
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let code = status.as_u16();
        let body = read_capped(response, MAX_ERROR_BODY).await;
        Err(error_from_http(code, &body, request.model(), timeout))
    }

    fn log_failure(&self, model: &str, error: &RuntimeError) {
        tracing::debug!(
            endpoint = %self.endpoint,
            model = %model,
            error_kind = error.kind(),
            "generation failed"
        );
    }
}

#[async_trait]
impl ModelRuntime for OllamaModelRuntime {
    async fn generate(
        &self,
        request: GenerationRequest,
    ) -> Result<GenerationResponse, RuntimeError> {
        if let Err(error) = request.validate() {
            self.log_failure(request.model(), &error);
            return Err(error);
        }
        let model = request.model().to_owned();
        let timeout = request.timeout().unwrap_or(self.request_timeout);
        let response = match self.send_chat(&request, false).await {
            Ok(response) => response,
            Err(error) => {
                self.log_failure(&model, &error);
                return Err(error);
            }
        };
        let body = match read_limited(response, MAX_SUCCESS_BODY, timeout).await {
            Ok(body) => body,
            Err(error) => {
                self.log_failure(&model, &error);
                return Err(error);
            }
        };
        match response_from_chat_json(&body, &model) {
            Ok(response) => {
                tracing::debug!(endpoint = %self.endpoint, model = %model, "generation finished");
                Ok(response)
            }
            Err(error) => {
                self.log_failure(&model, &error);
                Err(error)
            }
        }
    }

    async fn generate_stream(
        &self,
        request: GenerationRequest,
    ) -> Result<GenerationStream, RuntimeError> {
        if let Err(error) = request.validate() {
            self.log_failure(request.model(), &error);
            return Err(error);
        }
        let model = request.model().to_owned();
        let timeout = request.timeout().unwrap_or(self.request_timeout);
        let response = match self.send_chat(&request, true).await {
            Ok(response) => response,
            Err(error) => {
                self.log_failure(&model, &error);
                return Err(error);
            }
        };
        tracing::debug!(endpoint = %self.endpoint, model = %model, "generation stream started");
        let incoming = response.bytes_stream().map(move |item| {
            item.map(|bytes| bytes.to_vec())
                .map_err(|error| map_stream_transport(error, timeout))
        });
        let incoming: Pin<Box<dyn Stream<Item = Result<Vec<u8>, RuntimeError>> + Send>> =
            Box::pin(incoming);
        Ok(GenerationStream::from_stream(events_from_chunks(
            incoming,
            model,
            self.max_frame,
        )))
    }

    async fn capabilities(&self, model: &str) -> Result<ModelCapabilities, RuntimeError> {
        let probe = GenerationRequest::try_new(
            model,
            vec![lca_model_runtime::Message::user("capabilities")],
            lca_model_runtime::GenerationOptions::default(),
        );
        if let Err(error) = probe {
            self.log_failure(model, &error);
            return Err(error);
        }
        let timeout = self.request_timeout;
        let url = format!("{}/api/show", self.endpoint);
        let response = self
            .client
            .post(&url)
            .timeout(timeout)
            .json(&serde_json::json!({ "model": model }))
            .send()
            .await
            .map_err(|error| map_transport(error, timeout, &self.endpoint));
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                self.log_failure(model, &error);
                return Err(error);
            }
        };
        let status = response.status();
        if !status.is_success() {
            let code = status.as_u16();
            let body = read_capped(response, MAX_ERROR_BODY).await;
            let error = error_from_http(code, &body, model, timeout);
            self.log_failure(model, &error);
            return Err(error);
        }
        let body = match read_limited(response, MAX_SUCCESS_BODY, timeout).await {
            Ok(body) => body,
            Err(error) => {
                self.log_failure(model, &error);
                return Err(error);
            }
        };
        match capabilities_from_show(model, &body) {
            Ok(capabilities) => Ok(capabilities),
            Err(error) => {
                self.log_failure(model, &error);
                Err(error)
            }
        }
    }
}

fn map_transport(error: reqwest::Error, timeout: Duration, endpoint: &str) -> RuntimeError {
    if error.is_timeout() {
        RuntimeError::timeout(timeout, Some(Box::new(error)))
    } else if error.is_redirect() {
        RuntimeError::backend(None, "redirects are not followed")
    } else if error.is_decode() {
        RuntimeError::protocol("response body could not be decoded")
    } else {
        RuntimeError::connection(endpoint, error)
    }
}

fn map_stream_transport(error: reqwest::Error, timeout: Duration) -> RuntimeError {
    if error.is_timeout() {
        RuntimeError::timeout(timeout, Some(Box::new(error)))
    } else {
        RuntimeError::stream_interrupted(Some(Box::new(error)))
    }
}

async fn read_capped(response: reqwest::Response, limit: usize) -> Vec<u8> {
    let mut body = Vec::new();
    let mut incoming = response.bytes_stream();
    while body.len() < limit {
        match incoming.next().await {
            Some(Ok(chunk)) => {
                let room = limit - body.len();
                let take = chunk.len().min(room);
                body.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    break;
                }
            }
            Some(Err(_)) | None => break,
        }
    }
    body
}

async fn read_limited(
    response: reqwest::Response,
    limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, RuntimeError> {
    let mut body = Vec::new();
    let mut incoming = response.bytes_stream();
    while let Some(item) = incoming.next().await {
        let chunk = item.map_err(|error| map_stream_transport(error, timeout))?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(RuntimeError::protocol(format!(
                "response exceeds {limit} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_endpoints_fail_before_a_client_is_used() {
        let error = OllamaModelRuntime::connect(OllamaRuntimeConfig::new(
            "http://192.0.2.10:11434",
            Duration::from_secs(1),
            Duration::from_secs(1),
        ))
        .expect_err("remote");
        assert_eq!(error.kind(), "invalid_request");
        assert!(error.to_string().contains("loopback"), "{error}");
        assert!(!error.to_string().contains("super-secret-password"));
    }
}
