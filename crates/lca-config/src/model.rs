use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use url::{Host, Url};

use crate::error::ConfigError;

/// Default Ollama native API origin. This is not the OpenAI-compatible `/v1` URL.
pub const DEFAULT_OLLAMA_ENDPOINT: &str = "http://127.0.0.1:11434";

/// Default local model name.
pub const DEFAULT_OLLAMA_MODEL: &str = "lca-30b-agent";

/// Default context window, in tokens.
pub const DEFAULT_CONTEXT_WINDOW: u32 = 8192;

/// Default generation cap, in tokens.
pub const DEFAULT_GENERATION_LIMIT: u32 = 2048;

/// Default maximum number of future agent steps.
pub const DEFAULT_MAX_STEPS: u32 = 32;

/// Default overall agent timeout, in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Default per-request Ollama HTTP timeout, in seconds.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 5;

/// Default TCP connect timeout for one Ollama call, in seconds.
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Largest accepted context window, in tokens.
pub const MAX_CONTEXT_WINDOW: u32 = 1_048_576;

/// Largest accepted agent timeout, in seconds (24 hours).
pub const MAX_TIMEOUT_SECS: u64 = 24 * 60 * 60;

/// Largest accepted Ollama HTTP timeout, in seconds (1 hour).
pub const MAX_REQUEST_TIMEOUT_SECS: u64 = 60 * 60;

/// Largest accepted step budget.
pub const MAX_STEPS: u32 = 10_000;

/// Largest accepted configuration file, in bytes.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// Largest accepted model name, in bytes.
pub const MAX_MODEL_NAME_LEN: usize = 256;

/// Default maximum size of one text file, in bytes (1 MiB).
pub const DEFAULT_TOOL_MAX_FILE_SIZE_BYTES: u64 = 1_048_576;

/// Default maximum read response, in bytes (256 KiB).
pub const DEFAULT_TOOL_MAX_RESPONSE_BYTES: u64 = 262_144;

/// Default maximum directory entries returned.
pub const DEFAULT_TOOL_MAX_DIRECTORY_ENTRIES: usize = 1_000;

/// Default maximum search hits.
pub const DEFAULT_TOOL_MAX_SEARCH_MATCHES: usize = 100;

/// Default maximum files a search may read.
pub const DEFAULT_TOOL_MAX_SEARCH_FILES: usize = 1_000;

/// Default maximum bytes a search may read (32 MiB).
pub const DEFAULT_TOOL_MAX_SEARCH_TOTAL_BYTES: u64 = 33_554_432;

const MAX_TOOL_FILE_SIZE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOOL_DIRECTORY_ENTRIES: usize = 10_000;
const MAX_TOOL_SEARCH_MATCHES: usize = 10_000;
const MAX_TOOL_SEARCH_FILES: usize = 100_000;
const MAX_TOOL_SEARCH_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

const MAX_ENDPOINT_LEN: usize = 2048;

/// Validated agent configuration.
///
/// Fields stay private so a caller cannot replace the canonical workspace root or bypass
/// endpoint checks after loading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    workspace_root: PathBuf,
    endpoint: String,
    loopback_endpoint: bool,
    model: String,
    context_window: u32,
    generation_limit: u32,
    max_steps: u32,
    timeout: Duration,
    request_timeout: Duration,
    connect_timeout: Duration,
    tool_read_enabled: bool,
    tool_write_enabled: bool,
    tool_max_file_size_bytes: u64,
    tool_max_response_bytes: u64,
    tool_max_directory_entries: usize,
    tool_max_search_matches: usize,
    tool_max_search_files: usize,
    tool_max_search_total_bytes: u64,
}

/// Values that are safe to print and to record in diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSummary {
    /// Canonical workspace directory.
    pub workspace_root: PathBuf,
    /// Ollama origin without credentials or a path.
    pub endpoint: String,
    /// Whether the endpoint host is loopback.
    pub loopback_endpoint: bool,
    /// Model name.
    pub model: String,
    /// Context window in tokens.
    pub context_window: u32,
    /// Generation cap in tokens.
    pub generation_limit: u32,
    /// Step budget.
    pub max_steps: u32,
    /// Agent timeout in seconds.
    pub timeout_secs: u64,
    /// HTTP timeout in seconds.
    pub request_timeout_secs: u64,
    /// TCP connect timeout in seconds.
    pub connect_timeout_secs: u64,
    /// Whether read tools are enabled.
    pub tool_read_enabled: bool,
    /// Whether patch preparation is enabled. Application still requires approval.
    pub tool_write_enabled: bool,
    /// Write approval cannot be turned off.
    pub require_write_approval: bool,
    /// Maximum file size in bytes.
    pub tool_max_file_size_bytes: u64,
    /// Maximum read response in bytes.
    pub tool_max_response_bytes: u64,
    /// Maximum directory entries.
    pub tool_max_directory_entries: usize,
    /// Maximum search hits.
    pub tool_max_search_matches: usize,
    /// Maximum files a search may read.
    pub tool_max_search_files: usize,
    /// Maximum bytes a search may read.
    pub tool_max_search_total_bytes: u64,
}

impl AgentConfig {
    pub(crate) fn new(
        workspace_root: PathBuf,
        endpoint: CheckedEndpoint,
        model: String,
        limits: ResolvedLimits,
        tools: ResolvedTools,
    ) -> Self {
        Self {
            workspace_root,
            endpoint: endpoint.origin,
            loopback_endpoint: endpoint.loopback,
            model,
            context_window: limits.context_window,
            generation_limit: limits.generation_limit,
            max_steps: limits.max_steps,
            timeout: limits.timeout,
            request_timeout: limits.request_timeout,
            connect_timeout: limits.connect_timeout,
            tool_read_enabled: tools.read_enabled,
            tool_write_enabled: tools.write_enabled,
            tool_max_file_size_bytes: tools.max_file_size_bytes,
            tool_max_response_bytes: tools.max_response_bytes,
            tool_max_directory_entries: tools.max_directory_entries,
            tool_max_search_matches: tools.max_search_matches,
            tool_max_search_files: tools.max_search_files,
            tool_max_search_total_bytes: tools.max_search_total_bytes,
        }
    }

    /// Canonical workspace directory.
    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// Ollama origin, without a trailing slash or embedded credentials.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Whether the configured host is a loopback address or `localhost`.
    #[must_use]
    pub const fn loopback_endpoint(&self) -> bool {
        self.loopback_endpoint
    }

    /// Model name.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Context window in tokens.
    #[must_use]
    pub const fn context_window(&self) -> u32 {
        self.context_window
    }

    /// Generation cap in tokens.
    #[must_use]
    pub const fn generation_limit(&self) -> u32 {
        self.generation_limit
    }

    /// Maximum agent steps reserved for a later milestone.
    #[must_use]
    pub const fn max_steps(&self) -> u32 {
        self.max_steps
    }

    /// Overall agent timeout. The agent loop that would enforce it is not implemented.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// HTTP timeout for one Ollama call.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// TCP connect timeout for one Ollama call.
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Whether read tools may run. This does not approve writes.
    #[must_use]
    pub const fn tool_read_enabled(&self) -> bool {
        self.tool_read_enabled
    }

    /// Whether a patch may be prepared. Applying it still requires approval.
    #[must_use]
    pub const fn tool_write_enabled(&self) -> bool {
        self.tool_write_enabled
    }

    /// Always true. Configuration cannot disable write approval.
    #[must_use]
    pub const fn require_write_approval(&self) -> bool {
        true
    }

    /// Maximum file size in bytes.
    #[must_use]
    pub const fn tool_max_file_size_bytes(&self) -> u64 {
        self.tool_max_file_size_bytes
    }

    /// Maximum bytes returned by one read.
    #[must_use]
    pub const fn tool_max_response_bytes(&self) -> u64 {
        self.tool_max_response_bytes
    }

    /// Maximum directory entries returned.
    #[must_use]
    pub const fn tool_max_directory_entries(&self) -> usize {
        self.tool_max_directory_entries
    }

    /// Maximum search hits.
    #[must_use]
    pub const fn tool_max_search_matches(&self) -> usize {
        self.tool_max_search_matches
    }

    /// Maximum files a search may read.
    #[must_use]
    pub const fn tool_max_search_files(&self) -> usize {
        self.tool_max_search_files
    }

    /// Maximum bytes a search may read.
    #[must_use]
    pub const fn tool_max_search_total_bytes(&self) -> u64 {
        self.tool_max_search_total_bytes
    }

    /// Copy of the fields that diagnostics are allowed to show.
    #[must_use]
    pub fn summary(&self) -> ConfigSummary {
        ConfigSummary {
            workspace_root: self.workspace_root.clone(),
            endpoint: self.endpoint.clone(),
            loopback_endpoint: self.loopback_endpoint,
            model: self.model.clone(),
            context_window: self.context_window,
            generation_limit: self.generation_limit,
            max_steps: self.max_steps,
            timeout_secs: self.timeout.as_secs(),
            request_timeout_secs: self.request_timeout.as_secs(),
            connect_timeout_secs: self.connect_timeout.as_secs(),
            tool_read_enabled: self.tool_read_enabled,
            tool_write_enabled: self.tool_write_enabled,
            require_write_approval: true,
            tool_max_file_size_bytes: self.tool_max_file_size_bytes,
            tool_max_response_bytes: self.tool_max_response_bytes,
            tool_max_directory_entries: self.tool_max_directory_entries,
            tool_max_search_matches: self.tool_max_search_matches,
            tool_max_search_files: self.tool_max_search_files,
            tool_max_search_total_bytes: self.tool_max_search_total_bytes,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawConfig {
    pub(crate) workspace_root: Option<String>,
    #[serde(default)]
    pub(crate) ollama: RawOllama,
    #[serde(default)]
    pub(crate) limits: RawLimits,
    #[serde(default)]
    pub(crate) tools: RawTools,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawOllama {
    pub(crate) endpoint: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) context_window: Option<u32>,
    pub(crate) generation_limit: Option<u32>,
    pub(crate) request_timeout_secs: Option<u64>,
    pub(crate) connect_timeout_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawLimits {
    pub(crate) max_steps: Option<u32>,
    pub(crate) timeout_secs: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawTools {
    pub(crate) read_enabled: Option<bool>,
    pub(crate) write_enabled: Option<bool>,
    pub(crate) require_write_approval: Option<bool>,
    pub(crate) max_file_size_bytes: Option<u64>,
    pub(crate) max_response_bytes: Option<u64>,
    pub(crate) max_directory_entries: Option<u64>,
    pub(crate) max_search_matches: Option<u64>,
    pub(crate) max_search_files: Option<u64>,
    pub(crate) max_search_total_bytes: Option<u64>,
}

pub(crate) struct ResolvedTools {
    pub(crate) read_enabled: bool,
    pub(crate) write_enabled: bool,
    pub(crate) max_file_size_bytes: u64,
    pub(crate) max_response_bytes: u64,
    pub(crate) max_directory_entries: usize,
    pub(crate) max_search_matches: usize,
    pub(crate) max_search_files: usize,
    pub(crate) max_search_total_bytes: u64,
}

pub(crate) struct CheckedEndpoint {
    pub(crate) origin: String,
    pub(crate) loopback: bool,
}

pub(crate) struct ResolvedLimits {
    pub(crate) context_window: u32,
    pub(crate) generation_limit: u32,
    pub(crate) max_steps: u32,
    pub(crate) timeout: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) connect_timeout: Duration,
}

pub(crate) fn check_endpoint(value: &str) -> Result<CheckedEndpoint, ConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::InvalidEndpoint {
            message: "endpoint must not be empty".to_owned(),
        });
    }
    if trimmed.len() > MAX_ENDPOINT_LEN {
        return Err(ConfigError::InvalidEndpoint {
            message: "endpoint is too long".to_owned(),
        });
    }

    let url = Url::parse(trimmed).map_err(|_| ConfigError::InvalidEndpoint {
        message: "endpoint must be an http or https URL".to_owned(),
    })?;

    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(ConfigError::InvalidEndpoint {
            message: "scheme must be http or https".to_owned(),
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::EndpointCredentials);
    }
    if url.host_str().is_none() {
        return Err(ConfigError::InvalidEndpoint {
            message: "endpoint must include a host".to_owned(),
        });
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err(ConfigError::InvalidEndpoint {
            message: "endpoint path must be empty; use the Ollama origin, not a /v1 URL".to_owned(),
        });
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ConfigError::InvalidEndpoint {
            message: "endpoint must not include a query or fragment".to_owned(),
        });
    }

    let host = url.host_str().ok_or_else(|| ConfigError::InvalidEndpoint {
        message: "endpoint must include a host".to_owned(),
    })?;
    let origin = match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    };

    Ok(CheckedEndpoint {
        origin,
        loopback: host_is_loopback(&url),
    })
}

fn host_is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

pub(crate) fn check_model(value: &str) -> Result<String, ConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::InvalidValue {
            field: "ollama.model",
            message: "model name must not be empty".to_owned(),
        });
    }
    if trimmed.len() > MAX_MODEL_NAME_LEN {
        return Err(ConfigError::InvalidValue {
            field: "ollama.model",
            message: "model name is too long".to_owned(),
        });
    }
    if trimmed
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(ConfigError::InvalidValue {
            field: "ollama.model",
            message: "model name must not contain whitespace or control characters".to_owned(),
        });
    }
    Ok(trimmed.to_owned())
}

pub(crate) fn check_context_window(value: u32) -> Result<u32, ConfigError> {
    if value == 0 || value > MAX_CONTEXT_WINDOW {
        return Err(ConfigError::InvalidValue {
            field: "ollama.context_window",
            message: format!("must be from 1 through {MAX_CONTEXT_WINDOW}"),
        });
    }
    Ok(value)
}

pub(crate) fn check_generation_limit(value: u32, context_window: u32) -> Result<u32, ConfigError> {
    if value == 0 || value > context_window {
        return Err(ConfigError::InvalidValue {
            field: "ollama.generation_limit",
            message: "must be from 1 through the context window".to_owned(),
        });
    }
    Ok(value)
}

pub(crate) fn check_max_steps(value: u32) -> Result<u32, ConfigError> {
    if value == 0 || value > MAX_STEPS {
        return Err(ConfigError::InvalidValue {
            field: "limits.max_steps",
            message: format!("must be from 1 through {MAX_STEPS}"),
        });
    }
    Ok(value)
}

pub(crate) fn check_timeout_secs(value: u64) -> Result<Duration, ConfigError> {
    if value == 0 || value > MAX_TIMEOUT_SECS {
        return Err(ConfigError::InvalidValue {
            field: "limits.timeout_secs",
            message: format!("must be from 1 through {MAX_TIMEOUT_SECS} seconds"),
        });
    }
    Ok(Duration::from_secs(value))
}

pub(crate) fn check_request_timeout_secs(value: u64) -> Result<Duration, ConfigError> {
    check_bounded_secs(value, "ollama.request_timeout_secs")
}

pub(crate) fn check_connect_timeout_secs(value: u64) -> Result<Duration, ConfigError> {
    check_bounded_secs(value, "ollama.connect_timeout_secs")
}

pub(crate) fn resolve_tools(raw: &RawTools) -> Result<ResolvedTools, ConfigError> {
    if raw.require_write_approval == Some(false) {
        return Err(ConfigError::InvalidValue {
            field: "tools.require_write_approval",
            message: "write approval cannot be disabled".to_owned(),
        });
    }
    let max_file_size_bytes = bounded_u64(
        raw.max_file_size_bytes
            .unwrap_or(DEFAULT_TOOL_MAX_FILE_SIZE_BYTES),
        MAX_TOOL_FILE_SIZE_BYTES,
        "tools.max_file_size_bytes",
    )?;
    let max_response_bytes = bounded_u64(
        raw.max_response_bytes
            .unwrap_or(DEFAULT_TOOL_MAX_RESPONSE_BYTES),
        max_file_size_bytes,
        "tools.max_response_bytes",
    )?;
    Ok(ResolvedTools {
        read_enabled: raw.read_enabled.unwrap_or(true),
        write_enabled: raw.write_enabled.unwrap_or(true),
        max_file_size_bytes,
        max_response_bytes,
        max_directory_entries: bounded_count(
            raw.max_directory_entries,
            DEFAULT_TOOL_MAX_DIRECTORY_ENTRIES,
            MAX_TOOL_DIRECTORY_ENTRIES,
            "tools.max_directory_entries",
        )?,
        max_search_matches: bounded_count(
            raw.max_search_matches,
            DEFAULT_TOOL_MAX_SEARCH_MATCHES,
            MAX_TOOL_SEARCH_MATCHES,
            "tools.max_search_matches",
        )?,
        max_search_files: bounded_count(
            raw.max_search_files,
            DEFAULT_TOOL_MAX_SEARCH_FILES,
            MAX_TOOL_SEARCH_FILES,
            "tools.max_search_files",
        )?,
        max_search_total_bytes: bounded_u64(
            raw.max_search_total_bytes
                .unwrap_or(DEFAULT_TOOL_MAX_SEARCH_TOTAL_BYTES),
            MAX_TOOL_SEARCH_TOTAL_BYTES,
            "tools.max_search_total_bytes",
        )?,
    })
}

fn bounded_u64(value: u64, max: u64, field: &'static str) -> Result<u64, ConfigError> {
    if value == 0 || value > max {
        return Err(ConfigError::InvalidValue {
            field,
            message: format!("must be from 1 through {max}"),
        });
    }
    Ok(value)
}

fn bounded_count(
    value: Option<u64>,
    default: usize,
    max: usize,
    field: &'static str,
) -> Result<usize, ConfigError> {
    let Some(value) = value else {
        return Ok(default);
    };
    let count = usize::try_from(value).map_err(|_| ConfigError::InvalidValue {
        field,
        message: format!("must be from 1 through {max}"),
    })?;
    if count == 0 || count > max {
        return Err(ConfigError::InvalidValue {
            field,
            message: format!("must be from 1 through {max}"),
        });
    }
    Ok(count)
}

fn check_bounded_secs(value: u64, field: &'static str) -> Result<Duration, ConfigError> {
    if value == 0 || value > MAX_REQUEST_TIMEOUT_SECS {
        return Err(ConfigError::InvalidValue {
            field,
            message: format!("must be from 1 through {MAX_REQUEST_TIMEOUT_SECS} seconds"),
        });
    }
    Ok(Duration::from_secs(value))
}
