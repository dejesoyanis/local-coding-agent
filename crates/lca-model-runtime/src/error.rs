use std::error::Error;
use std::time::Duration;

/// Failure produced by a model runtime.
///
/// Expected failures are values of this type. Library paths do not panic for them.
/// [`report`] is the operator-facing text and includes the source chain.
/// Response bodies are not stored on these variants.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// The runtime could not establish a connection.
    #[error("cannot connect to the model runtime at {endpoint}")]
    Connection {
        /// Origin that was contacted, without credentials.
        endpoint: String,
        /// Transport failure.
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },

    /// The configured deadline elapsed before the backend finished.
    #[error("model runtime timed out after {timeout:?}")]
    Timeout {
        /// Deadline that elapsed.
        timeout: Duration,
        /// Transport failure, when the backend reported one.
        #[source]
        source: Option<Box<dyn Error + Send + Sync>>,
    },

    /// The backend does not have the requested model.
    #[error("{message}")]
    ModelNotFound {
        /// Model identifier from the request.
        model: String,
        /// Short backend explanation, when one was supplied as a structured error field.
        detail: Option<String>,
        /// Display text. It repeats `model` and `detail` without a response body.
        message: String,
    },

    /// The request cannot be sent because it violates the runtime contract.
    ///
    /// Adapters must not retry this variant. The message does not include prompt text.
    #[error("invalid generation request: {message}")]
    InvalidRequest {
        /// Validation or protocol reason.
        message: String,
    },

    /// The backend accepted the connection and then failed.
    #[error("model backend failed: {message}")]
    BackendFailure {
        /// HTTP status, when the failure came from an HTTP response.
        status: Option<u16>,
        /// Sanitized explanation, including the status when one exists.
        message: String,
    },

    /// The backend sent bytes that do not match the agreed response shape.
    #[error("model backend violated the response protocol: {message}")]
    ProtocolViolation {
        /// What was wrong. The raw payload is omitted.
        message: String,
        /// Specific classification. [`Self::kind`] stays `protocol_violation`.
        code: &'static str,
    },

    /// A stream ended before the backend emitted a terminal completion.
    ///
    /// This is not a successful generation.
    #[error("generation stream ended before a terminal completion")]
    StreamInterrupted {
        /// Transport failure, when one caused the interruption.
        #[source]
        source: Option<Box<dyn Error + Send + Sync>>,
    },
}

impl RuntimeError {
    /// Stable classification that does not include request or response text.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Connection { .. } => "connection",
            Self::Timeout { .. } => "timeout",
            Self::ModelNotFound { .. } => "model_not_found",
            Self::InvalidRequest { .. } => "invalid_request",
            Self::BackendFailure { .. } => "backend_failure",
            Self::ProtocolViolation { .. } => "protocol_violation",
            Self::StreamInterrupted { .. } => "stream_interrupted",
        }
    }

    /// Specific classification.
    ///
    /// For [`Self::ProtocolViolation`] this can be narrower than [`Self::kind`].
    /// `invalid_http_json` means the HTTP body was not JSON. It is not the assistant
    /// document, which the controller classifies as `invalid_json`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ProtocolViolation { code, .. } => code,
            _ => self.kind(),
        }
    }

    /// Connection failure. `endpoint` is recorded without reading a response body.
    pub fn connection(
        endpoint: impl Into<String>,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self::Connection {
            endpoint: endpoint.into(),
            source: Box::new(source),
        }
    }

    /// Deadline failure.
    #[must_use]
    pub fn timeout(timeout: Duration, source: Option<Box<dyn Error + Send + Sync>>) -> Self {
        Self::Timeout { timeout, source }
    }

    /// Missing model. `detail` must already be sanitized.
    #[must_use]
    pub fn model_not_found(model: impl Into<String>, detail: Option<String>) -> Self {
        let model = model.into();
        let message = match &detail {
            Some(text) if !text.is_empty() => format!("model `{model}` was not found: {text}"),
            _ => format!("model `{model}` was not found"),
        };
        Self::ModelNotFound {
            model,
            detail,
            message,
        }
    }

    /// Contract or semantically invalid request. Callers must not retry it.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidRequest {
            message: message.into(),
        }
    }

    /// Backend failure whose message is safe to print.
    pub fn backend(status: Option<u16>, message: impl Into<String>) -> Self {
        let detail = message.into();
        let message = match status {
            Some(code) => format!("HTTP {code}: {detail}"),
            None => detail,
        };
        Self::BackendFailure { status, message }
    }

    /// Response that cannot be interpreted. The code is `protocol_violation`.
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::protocol_code("protocol_violation", message)
    }

    /// Response that cannot be interpreted, with a specific [`Self::code`].
    ///
    /// [`Self::kind`] remains `protocol_violation`. The message must not include a body.
    pub fn protocol_code(code: &'static str, message: impl Into<String>) -> Self {
        Self::ProtocolViolation {
            message: message.into(),
            code,
        }
    }

    /// Stream that stopped before a terminal completion.
    #[must_use]
    pub fn stream_interrupted(source: Option<Box<dyn Error + Send + Sync>>) -> Self {
        Self::StreamInterrupted { source }
    }
}

impl PartialEq for RuntimeError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Connection { endpoint, .. },
                Self::Connection {
                    endpoint: other_endpoint,
                    ..
                },
            ) => endpoint == other_endpoint,
            (
                Self::Timeout { timeout, .. },
                Self::Timeout {
                    timeout: other_timeout,
                    ..
                },
            ) => timeout == other_timeout,
            (
                Self::ModelNotFound { model, detail, .. },
                Self::ModelNotFound {
                    model: other_model,
                    detail: other_detail,
                    ..
                },
            ) => model == other_model && detail == other_detail,
            (
                Self::InvalidRequest { message },
                Self::InvalidRequest {
                    message: other_message,
                },
            ) => message == other_message,
            (
                Self::BackendFailure { status, message },
                Self::BackendFailure {
                    status: other_status,
                    message: other_message,
                },
            ) => status == other_status && message == other_message,
            (
                Self::ProtocolViolation { message, code },
                Self::ProtocolViolation {
                    message: other_message,
                    code: other_code,
                },
            ) => message == other_message && code == other_code,
            (Self::StreamInterrupted { .. }, Self::StreamInterrupted { .. }) => true,
            _ => false,
        }
    }
}

impl Eq for RuntimeError {}

/// Display text plus up to four source errors.
///
/// Sources are included so operators can see the transport cause. Callers still must not
/// place raw response bodies on the source chain.
#[must_use]
pub fn report(error: &RuntimeError) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    let mut depth = 0;
    while let Some(inner) = source {
        if depth == 4 {
            break;
        }
        text.push_str(": ");
        text.push_str(&inner.to_string());
        source = inner.source();
        depth += 1;
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_and_report_keep_the_source_chain() {
        let error = RuntimeError::connection(
            "http://127.0.0.1:9",
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused"),
        );
        assert_eq!(error.kind(), "connection");
        let rendered = report(&error);
        assert!(rendered.contains("127.0.0.1:9"), "{rendered}");
        assert!(rendered.contains("connection refused"), "{rendered}");
        assert!(!rendered.contains("super-secret-password"), "{rendered}");
    }

    #[test]
    fn invalid_request_display_does_not_need_a_source() {
        let error = RuntimeError::invalid("model name must not be empty");
        assert_eq!(error.kind(), "invalid_request");
        assert_eq!(report(&error), error.to_string());
        assert!(error.to_string().contains("model name must not be empty"));
    }

    #[test]
    fn model_not_found_includes_a_sanitized_detail() {
        let error = RuntimeError::model_not_found(
            "lca-agent",
            Some("model 'lca-agent' not found".to_owned()),
        );
        assert_eq!(error.kind(), "model_not_found");
        assert!(error.to_string().contains("lca-agent"));
        assert!(error.to_string().contains("not found"));
    }

    #[test]
    fn equality_ignores_transport_sources() {
        let left = RuntimeError::stream_interrupted(None);
        let right = RuntimeError::stream_interrupted(Some(Box::new(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "eof",
        ))));
        assert_eq!(left, right);
        assert_ne!(left.kind(), RuntimeError::invalid("x").kind());
    }
}
