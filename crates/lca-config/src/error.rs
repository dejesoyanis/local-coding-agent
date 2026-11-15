use std::path::PathBuf;

/// Configuration load or validation failure.
///
/// Display text for credential rejection is static so a password embedded in an endpoint
/// cannot be copied into logs or command output from this error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The configuration path does not exist.
    #[error("configuration file {path} does not exist")]
    NotFound {
        /// Path that was requested.
        path: PathBuf,
    },

    /// The path exists but is not a regular file.
    #[error("configuration file {path} is not a regular file")]
    NotAFile {
        /// Path that was requested.
        path: PathBuf,
    },

    /// Reading the file failed.
    #[error("failed to read configuration {path}: {message}")]
    Io {
        /// Path that was requested.
        path: PathBuf,
        /// Filesystem error text, which does not include file contents.
        message: String,
    },

    /// The file is larger than [`crate::MAX_CONFIG_BYTES`].
    #[error("configuration file {path} exceeds {limit} bytes")]
    TooLarge {
        /// Path that was requested.
        path: PathBuf,
        /// Accepted maximum in bytes.
        limit: u64,
    },

    /// TOML syntax or types did not match the schema.
    #[error("failed to parse configuration {path}: {message}")]
    Parse {
        /// Path that was requested.
        path: PathBuf,
        /// Parser diagnostic. Configuration files are not a secret store.
        message: String,
    },

    /// `workspace_root` was absent or empty.
    #[error("configuration {path} is missing workspace_root")]
    MissingWorkspaceRoot {
        /// Path of the configuration file.
        path: PathBuf,
    },

    /// The workspace path does not exist.
    #[error("workspace root {path} does not exist")]
    WorkspaceNotFound {
        /// Path that was requested, after relative resolution.
        path: PathBuf,
    },

    /// The workspace path exists and is not a directory.
    #[error("workspace root {path} is not a directory")]
    WorkspaceNotDirectory {
        /// Path that was requested.
        path: PathBuf,
    },

    /// The workspace path could not be canonicalized.
    #[error("workspace root {path} cannot be canonicalized: {message}")]
    InvalidWorkspace {
        /// Path that was requested.
        path: PathBuf,
        /// Filesystem error text.
        message: String,
    },

    /// The endpoint contained a username or password.
    #[error("Ollama endpoint must not contain embedded credentials")]
    EndpointCredentials,

    /// The endpoint is not an origin the client can call.
    #[error("Ollama endpoint is invalid: {message}")]
    InvalidEndpoint {
        /// Reason the endpoint was rejected. The raw value is omitted.
        message: String,
    },

    /// A numeric or textual field failed validation.
    #[error("configuration field {field} is invalid: {message}")]
    InvalidValue {
        /// Field name.
        field: &'static str,
        /// Validation reason.
        message: String,
    },
}

impl ConfigError {
    /// Stable classification used in diagnostics. It never includes file contents.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::NotFound { .. } => "not_found",
            Self::NotAFile { .. } => "not_a_file",
            Self::Io { .. } => "io",
            Self::TooLarge { .. } => "too_large",
            Self::Parse { .. } => "parse",
            Self::MissingWorkspaceRoot { .. } => "missing_workspace_root",
            Self::WorkspaceNotFound { .. } => "workspace_not_found",
            Self::WorkspaceNotDirectory { .. } => "workspace_not_directory",
            Self::InvalidWorkspace { .. } => "invalid_workspace",
            Self::EndpointCredentials => "endpoint_credentials",
            Self::InvalidEndpoint { .. } => "invalid_endpoint",
            Self::InvalidValue { .. } => "invalid_value",
        }
    }
}
