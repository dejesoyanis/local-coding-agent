use std::fmt;

/// Failure while constructing a client.
///
/// Operational failures (offline server, bad JSON, missing model) are reported as
/// [`OllamaAvailability`] so a status command can print them without treating them as panics.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OllamaError {
    /// The endpoint was empty after trimming.
    #[error("Ollama endpoint must not be empty")]
    EmptyEndpoint,

    /// The endpoint exceeded the accepted length.
    #[error("Ollama endpoint is too long")]
    EndpointTooLong,

    /// The value was not an absolute URL.
    #[error("Ollama endpoint must be an http or https URL")]
    InvalidUrl,

    /// The URL scheme was not http or https.
    #[error("Ollama endpoint scheme must be http or https")]
    InvalidScheme,

    /// A username or password was embedded in the URL.
    #[error("Ollama endpoint must not contain embedded credentials")]
    EndpointCredentials,

    /// The URL had no host.
    #[error("Ollama endpoint must include a host")]
    MissingHost,

    /// The URL had a path. The native API origin must not include `/v1`.
    #[error("Ollama endpoint path must be empty")]
    UnexpectedPath,

    /// The URL had a query string or fragment.
    #[error("Ollama endpoint must not include a query or fragment")]
    UnexpectedQuery,

    /// A timeout of zero cannot bound a request.
    #[error("Ollama timeout must be greater than zero")]
    InvalidTimeout,
}

/// Result of a health and model-availability check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OllamaAvailability {
    /// The server responded and advertises the requested model.
    Ready {
        /// Value of `/api/version`.
        version: String,
    },
    /// The server responded and does not advertise the requested model.
    ModelMissing {
        /// Value of `/api/version`.
        version: String,
    },
    /// The server could not be used. `message` never includes a response body.
    Unavailable {
        /// Short reason safe to print.
        message: String,
    },
}

impl OllamaAvailability {
    /// Stable status word for command output.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Ready { .. } => "ready",
            Self::ModelMissing { .. } => "model_missing",
            Self::Unavailable { .. } => "unavailable",
        }
    }

    /// One-line explanation for command output.
    #[must_use]
    pub fn detail(&self, model: &str) -> String {
        match self {
            Self::Ready { version } => format!("version {version}"),
            Self::ModelMissing { version } => format!("version {version} does not list {model}"),
            Self::Unavailable { message } => message.clone(),
        }
    }
}

impl fmt::Display for OllamaAvailability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
