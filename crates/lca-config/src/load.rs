use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::ConfigError;
use crate::model::{
    AgentConfig, DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_CONTEXT_WINDOW, DEFAULT_GENERATION_LIMIT,
    DEFAULT_MAX_STEPS, DEFAULT_OLLAMA_ENDPOINT, DEFAULT_OLLAMA_MODEL, DEFAULT_REQUEST_TIMEOUT_SECS,
    DEFAULT_TIMEOUT_SECS, MAX_CONFIG_BYTES, RawConfig, ResolvedLimits, check_connect_timeout_secs,
    check_context_window, check_endpoint, check_generation_limit, check_max_steps, check_model,
    check_request_timeout_secs, check_timeout_secs, resolve_tools,
};
use crate::pathutil::simplify_verbatim;

/// Loads and validates a TOML configuration file.
///
/// Relative `workspace_root` values are resolved against the configuration file's directory,
/// then the path must exist, be a directory, and is replaced by its canonical form.
/// Missing Ollama and limit fields receive the documented defaults.
///
/// ```toml
/// workspace_root = "C:/path/to/workspace"
///
/// [ollama]
/// endpoint = "http://127.0.0.1:11434"
/// model = "lca-30b-agent"
/// context_window = 8192
/// generation_limit = 2048
/// request_timeout_secs = 5
/// connect_timeout_secs = 5
///
/// [limits]
/// max_steps = 32
/// timeout_secs = 300
/// ```
pub fn load_from_path(path: &Path) -> Result<AgentConfig, ConfigError> {
    match load_inner(path) {
        Ok(config) => {
            let summary = config.summary();
            if !summary.loopback_endpoint {
                tracing::warn!(
                    endpoint = %summary.endpoint,
                    "Ollama endpoint is not a loopback address"
                );
            }
            tracing::info!(
                workspace_root = %summary.workspace_root.display(),
                endpoint = %summary.endpoint,
                model = %summary.model,
                context_window = summary.context_window,
                generation_limit = summary.generation_limit,
                max_steps = summary.max_steps,
                timeout_secs = summary.timeout_secs,
                request_timeout_secs = summary.request_timeout_secs,
                connect_timeout_secs = summary.connect_timeout_secs,
                "configuration loaded"
            );
            Ok(config)
        }
        Err(error) => {
            tracing::debug!(error_kind = error.kind(), "configuration rejected");
            Err(error)
        }
    }
}

fn load_inner(path: &Path) -> Result<AgentConfig, ConfigError> {
    let absolute = absolute_config_path(path)?;
    let text = read_config_text(&absolute)?;
    let raw: RawConfig = toml::from_str(&text).map_err(|error| ConfigError::Parse {
        path: absolute.clone(),
        message: error.to_string(),
    })?;

    let workspace_value = raw
        .workspace_root
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ConfigError::MissingWorkspaceRoot {
            path: absolute.clone(),
        })?;

    let endpoint = check_endpoint(
        raw.ollama
            .endpoint
            .as_deref()
            .unwrap_or(DEFAULT_OLLAMA_ENDPOINT),
    )?;
    let model = check_model(raw.ollama.model.as_deref().unwrap_or(DEFAULT_OLLAMA_MODEL))?;
    let context_window =
        check_context_window(raw.ollama.context_window.unwrap_or(DEFAULT_CONTEXT_WINDOW))?;
    let generation_limit = check_generation_limit(
        raw.ollama
            .generation_limit
            .unwrap_or(DEFAULT_GENERATION_LIMIT),
        context_window,
    )?;
    let request_timeout = check_request_timeout_secs(
        raw.ollama
            .request_timeout_secs
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS),
    )?;
    let connect_timeout = check_connect_timeout_secs(
        raw.ollama
            .connect_timeout_secs
            .unwrap_or(DEFAULT_CONNECT_TIMEOUT_SECS),
    )?;
    let max_steps = check_max_steps(raw.limits.max_steps.unwrap_or(DEFAULT_MAX_STEPS))?;
    let timeout = check_timeout_secs(raw.limits.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS))?;
    let tools = resolve_tools(&raw.tools)?;

    let config_dir = absolute.parent().ok_or_else(|| ConfigError::Io {
        path: absolute.clone(),
        message: "configuration path has no parent directory".to_owned(),
    })?;
    let workspace_root = canonicalize_workspace(config_dir, Path::new(workspace_value))?;

    Ok(AgentConfig::new(
        workspace_root,
        endpoint,
        model,
        ResolvedLimits {
            context_window,
            generation_limit,
            max_steps,
            timeout,
            request_timeout,
            connect_timeout,
        },
        tools,
    ))
}

fn absolute_config_path(path: &Path) -> Result<PathBuf, ConfigError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let current = std::env::current_dir().map_err(|error| ConfigError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    Ok(current.join(path))
}

fn read_config_text(path: &Path) -> Result<String, ConfigError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConfigError::NotFound {
                path: path.to_path_buf(),
            });
        }
        Err(error) => {
            return Err(ConfigError::Io {
                path: path.to_path_buf(),
                message: error.to_string(),
            });
        }
    };
    if !metadata.is_file() {
        return Err(ConfigError::NotAFile {
            path: path.to_path_buf(),
        });
    }

    let file = File::open(path).map_err(|error| ConfigError::Io {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    let mut reader = file.take(MAX_CONFIG_BYTES + 1);
    let mut text = String::new();
    reader
        .read_to_string(&mut text)
        .map_err(|error| ConfigError::Io {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
    if text.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge {
            path: path.to_path_buf(),
            limit: MAX_CONFIG_BYTES,
        });
    }
    Ok(text)
}

fn canonicalize_workspace(config_dir: &Path, workspace: &Path) -> Result<PathBuf, ConfigError> {
    let candidate = if workspace.is_absolute() {
        workspace.to_path_buf()
    } else {
        config_dir.join(workspace)
    };

    let metadata = match std::fs::metadata(&candidate) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ConfigError::WorkspaceNotFound { path: candidate });
        }
        Err(error) => {
            return Err(ConfigError::InvalidWorkspace {
                path: candidate,
                message: error.to_string(),
            });
        }
    };
    if !metadata.is_dir() {
        return Err(ConfigError::WorkspaceNotDirectory { path: candidate });
    }

    let canonical =
        std::fs::canonicalize(&candidate).map_err(|error| ConfigError::InvalidWorkspace {
            path: candidate.clone(),
            message: error.to_string(),
        })?;
    let simplified = simplify_verbatim(canonical);
    if !simplified.is_dir() {
        return Err(ConfigError::WorkspaceNotDirectory { path: simplified });
    }
    Ok(simplified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ConfigError;
    use crate::model::{
        DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_CONTEXT_WINDOW, DEFAULT_GENERATION_LIMIT,
        DEFAULT_MAX_STEPS, DEFAULT_OLLAMA_ENDPOINT, DEFAULT_OLLAMA_MODEL,
        DEFAULT_REQUEST_TIMEOUT_SECS, DEFAULT_TIMEOUT_SECS, MAX_CONFIG_BYTES,
    };
    use crate::pathutil::simplify_verbatim;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "lca-config-{label}-{}-{nanos}-{id}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_config(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("lca.toml");
        std::fs::write(&path, body).expect("write config");
        path
    }

    fn toml_path(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }

    #[test]
    fn applies_documented_defaults_and_canonicalizes_relative_root() {
        let root = TempDir::new("defaults");
        let config_dir = root.path().join("cfg");
        std::fs::create_dir(&config_dir).expect("cfg");
        let workspace = config_dir.join("workspace");
        std::fs::create_dir(&workspace).expect("workspace");
        let path = write_config(&config_dir, "workspace_root = 'workspace'\n");

        let config = load_from_path(&path).expect("load");
        let expected = simplify_verbatim(std::fs::canonicalize(&workspace).expect("canonical"));
        assert_eq!(config.workspace_root(), expected.as_path());
        assert_eq!(config.endpoint(), DEFAULT_OLLAMA_ENDPOINT);
        assert_eq!(config.model(), DEFAULT_OLLAMA_MODEL);
        assert_eq!(config.context_window(), DEFAULT_CONTEXT_WINDOW);
        assert!(config.loopback_endpoint());
        assert_eq!(config.generation_limit(), DEFAULT_GENERATION_LIMIT);
        assert_eq!(config.max_steps(), DEFAULT_MAX_STEPS);
        assert_eq!(config.timeout().as_secs(), DEFAULT_TIMEOUT_SECS);
        assert_eq!(
            config.request_timeout().as_secs(),
            DEFAULT_REQUEST_TIMEOUT_SECS
        );
        assert_eq!(
            config.connect_timeout().as_secs(),
            DEFAULT_CONNECT_TIMEOUT_SECS
        );
        assert!(config.tool_read_enabled());
        assert!(config.tool_write_enabled());
        assert!(config.require_write_approval());
        assert_eq!(
            config.tool_max_file_size_bytes(),
            crate::DEFAULT_TOOL_MAX_FILE_SIZE_BYTES
        );
        assert_eq!(
            config.tool_max_response_bytes(),
            crate::DEFAULT_TOOL_MAX_RESPONSE_BYTES
        );
        assert_eq!(config.tool_max_search_matches(), 100);
    }

    #[test]
    fn tools_section_rejects_disabled_approval_and_zero_limits() {
        let root = TempDir::new("tools");
        let workspace = root.path().join("ws");
        std::fs::create_dir(&workspace).expect("workspace");
        let base = toml_path(&workspace);
        let disabled = write_config(
            root.path(),
            &format!("workspace_root = '{base}'\n[tools]\nrequire_write_approval = false\n"),
        );
        let error = load_from_path(&disabled).expect_err("approval");
        assert_eq!(error.kind(), "invalid_value");
        assert!(error.to_string().contains("cannot be disabled"), "{error}");

        let zero = write_config(
            root.path(),
            &format!("workspace_root = '{base}'\n[tools]\nmax_file_size_bytes = 0\n"),
        );
        assert_eq!(
            load_from_path(&zero).expect_err("zero").kind(),
            "invalid_value"
        );

        let explicit = write_config(
            root.path(),
            &format!(
                "workspace_root = '{base}'\n[tools]\nread_enabled = false\nwrite_enabled = true\nmax_file_size_bytes = 128\nmax_response_bytes = 64\nmax_directory_entries = 3\nmax_search_matches = 4\nmax_search_files = 5\nmax_search_total_bytes = 256\nrequire_write_approval = true\n"
            ),
        );
        let config = load_from_path(&explicit).expect("explicit");
        assert!(!config.tool_read_enabled());
        assert!(config.tool_write_enabled());
        assert!(config.require_write_approval());
        assert_eq!(config.tool_max_file_size_bytes(), 128);
        assert_eq!(config.tool_max_response_bytes(), 64);
        assert_eq!(config.tool_max_directory_entries(), 3);
        assert_eq!(config.tool_max_search_matches(), 4);
        assert_eq!(config.tool_max_search_files(), 5);
        assert_eq!(config.tool_max_search_total_bytes(), 256);
        assert!(config.privacy_excludes().is_empty());
    }

    #[test]
    fn privacy_excludes_are_additive_and_invalid_patterns_fail_closed() {
        let root = TempDir::new("privacy");
        let workspace = root.path().join("ws");
        std::fs::create_dir(&workspace).expect("workspace");
        let base = toml_path(&workspace);
        let accepted = write_config(
            root.path(),
            &format!(
                "workspace_root = '{base}'\n[tools]\nprivacy_excludes = ['notes/*.secret', 'private/**']\n"
            ),
        );
        let config = load_from_path(&accepted).expect("patterns");
        assert_eq!(config.privacy_excludes(), ["notes/*.secret", "private/**"]);
        assert!(config.require_write_approval());

        let rejected = write_config(
            root.path(),
            &format!("workspace_root = '{base}'\n[tools]\nprivacy_excludes = ['../secrets']\n"),
        );
        let error = load_from_path(&rejected).expect_err("pattern");
        assert_eq!(error.kind(), "invalid_value");

        let disabled = write_config(
            root.path(),
            &format!("workspace_root = '{base}'\n[tools]\nprivacy_enabled = false\n"),
        );
        assert_eq!(
            load_from_path(&disabled).expect_err("baseline").kind(),
            "parse"
        );
    }

    #[test]
    fn reads_explicit_values_and_trims_endpoint_and_model() {
        let root = TempDir::new("explicit");
        let workspace = root.path().join("ws");
        std::fs::create_dir(&workspace).expect("workspace");
        let body = format!(
            "workspace_root = '{}'\n\n[ollama]\nendpoint = ' http://127.0.0.1:11434/ '\nmodel = ' lca-30b-agent '\ncontext_window = 4096\ngeneration_limit = 512\nrequest_timeout_secs = 9\n\n[limits]\nmax_steps = 4\ntimeout_secs = 60\n",
            toml_path(&workspace)
        );
        let path = write_config(root.path(), &body);
        let config = load_from_path(&path).expect("load");
        assert_eq!(config.endpoint(), "http://127.0.0.1:11434");
        assert_eq!(config.model(), "lca-30b-agent");
        assert_eq!(config.context_window(), 4096);
        assert_eq!(config.generation_limit(), 512);
        assert_eq!(config.max_steps(), 4);
        assert_eq!(config.timeout().as_secs(), 60);
        assert_eq!(config.request_timeout().as_secs(), 9);
    }

    #[test]
    fn rejects_missing_nonexistent_and_non_directory_workspace_roots() {
        let root = TempDir::new("reject-root");
        let missing_key = write_config(root.path(), "\n");
        assert_eq!(
            load_from_path(&missing_key).expect_err("missing").kind(),
            "missing_workspace_root"
        );

        let empty = write_config(root.path(), "workspace_root = '   '\n");
        assert_eq!(
            load_from_path(&empty).expect_err("empty").kind(),
            "missing_workspace_root"
        );

        let absent = write_config(root.path(), "workspace_root = 'does-not-exist'\n");
        assert_eq!(
            load_from_path(&absent).expect_err("absent").kind(),
            "workspace_not_found"
        );

        let file_root = root.path().join("not-a-dir");
        std::fs::write(&file_root, "x").expect("file");
        let file_config = write_config(
            root.path(),
            &format!("workspace_root = '{}'\n", toml_path(&file_root)),
        );
        assert_eq!(
            load_from_path(&file_config).expect_err("file").kind(),
            "workspace_not_directory"
        );
    }

    #[test]
    fn rejects_invalid_endpoints_without_echoing_credentials() {
        let root = TempDir::new("endpoint");
        let workspace = root.path().join("ws");
        std::fs::create_dir(&workspace).expect("workspace");
        let base = toml_path(&workspace);

        let cases = [
            ("ftp://127.0.0.1:11434", "invalid_endpoint"),
            ("http://127.0.0.1:11434/v1", "invalid_endpoint"),
            ("http://127.0.0.1:11434?x=1", "invalid_endpoint"),
            ("http://", "invalid_endpoint"),
        ];
        for (endpoint, kind) in cases {
            let path = write_config(
                root.path(),
                &format!("workspace_root = '{base}'\n[ollama]\nendpoint = '{endpoint}'\n"),
            );
            let error = load_from_path(&path).expect_err(endpoint);
            assert_eq!(error.kind(), kind, "{endpoint}");
        }

        let path = write_config(
            root.path(),
            &format!(
                "workspace_root = '{base}'\n[ollama]\nendpoint = 'http://user:super-secret-password@127.0.0.1:11434'\n"
            ),
        );
        let error = load_from_path(&path).expect_err("credentials");
        assert_eq!(error.kind(), "endpoint_credentials");
        assert!(!error.to_string().contains("super-secret-password"));
    }

    #[test]
    fn rejects_invalid_limits_and_model_names() {
        let root = TempDir::new("limits");
        let workspace = root.path().join("ws");
        std::fs::create_dir(&workspace).expect("workspace");
        let base = toml_path(&workspace);

        let cases = [
            ("model = 'bad name'\n", "invalid_value"),
            ("context_window = 0\n", "invalid_value"),
            (
                "context_window = 10\ngeneration_limit = 11\n",
                "invalid_value",
            ),
            ("request_timeout_secs = 0\n", "invalid_value"),
            ("connect_timeout_secs = 0\n", "invalid_value"),
        ];
        for (ollama, kind) in cases {
            let path = write_config(
                root.path(),
                &format!("workspace_root = '{base}'\n[ollama]\n{ollama}"),
            );
            assert_eq!(load_from_path(&path).expect_err("ollama").kind(), kind);
        }

        let path = write_config(
            root.path(),
            &format!("workspace_root = '{base}'\n[limits]\ntimeout_secs = 0\n"),
        );
        assert_eq!(
            load_from_path(&path).expect_err("timeout").kind(),
            "invalid_value"
        );

        let path = write_config(
            root.path(),
            &format!("workspace_root = '{base}'\n[limits]\nmax_steps = 0\n"),
        );
        assert_eq!(
            load_from_path(&path).expect_err("steps").kind(),
            "invalid_value"
        );
    }

    #[test]
    fn accepts_non_loopback_endpoint() {
        let root = TempDir::new("remote");
        let workspace = root.path().join("ws");
        std::fs::create_dir(&workspace).expect("workspace");
        let path = write_config(
            root.path(),
            &format!(
                "workspace_root = '{}'\n[ollama]\nendpoint = 'http://192.0.2.10:11434'\n",
                toml_path(&workspace)
            ),
        );
        let config = load_from_path(&path).expect("load");
        assert_eq!(config.endpoint(), "http://192.0.2.10:11434");
        assert!(!config.loopback_endpoint());
    }

    #[test]
    fn rejects_unknown_fields_invalid_toml_missing_file_and_directory() {
        let root = TempDir::new("parse");
        let workspace = root.path().join("ws");
        std::fs::create_dir(&workspace).expect("workspace");
        let unknown = write_config(
            root.path(),
            &format!(
                "workspace_root = '{}'\napi_key = 'x'\n",
                toml_path(&workspace)
            ),
        );
        assert_eq!(
            load_from_path(&unknown).expect_err("unknown").kind(),
            "parse"
        );

        let broken = write_config(root.path(), "workspace_root = [\n");
        assert_eq!(load_from_path(&broken).expect_err("toml").kind(), "parse");

        let missing = root.path().join("missing.toml");
        assert_eq!(
            load_from_path(&missing).expect_err("missing").kind(),
            "not_found"
        );

        assert_eq!(
            load_from_path(root.path()).expect_err("dir").kind(),
            "not_a_file"
        );
    }

    #[test]
    fn rejects_oversized_files_before_parsing_them_as_config() {
        let root = TempDir::new("large");
        let path = root.path().join("lca.toml");
        let mut contents = vec![b' '; (MAX_CONFIG_BYTES + 1) as usize];
        contents[0] = b'#';
        std::fs::write(&path, contents).expect("write");
        let error = load_from_path(&path).expect_err("large");
        assert_eq!(error.kind(), "too_large");
        assert!(matches!(
            error,
            ConfigError::TooLarge {
                limit: MAX_CONFIG_BYTES,
                ..
            }
        ));
    }
}
