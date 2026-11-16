//! `lca eval tools` repeats read-only single-turn samples.
//!
//! The command forces patch preparation off. It does not commit a patch, does not run a
//! shell, and does not start a second model turn for a failed sample. The next sample is
//! a new turn, not a retry.

use std::path::PathBuf;

use lca_config::{AgentConfig, load_from_path};
use lca_core::{
    EvalExecution, EvalIdentity, EvalPlan, TurnSettings, evaluate_agent_runs,
    evaluate_tool_selection,
};
use lca_model_runtime::{ProtocolPreference, RuntimeError, report};
use lca_ollama::{HttpOllamaClient, OllamaModelRuntime, OllamaRuntimeConfig};
use lca_tools::ToolRegistry;

use crate::CommandOutput;
use crate::tools_cmd::{limits_from, sandbox_from};

/// Arguments for `lca eval tools`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalCommand {
    /// Configuration file.
    pub config: PathBuf,
    /// Requested protocol.
    pub protocol: ProtocolPreference,
    /// Independent samples per case.
    pub runs: u32,
    /// Report path. `None` uses `target/lca-eval/tool-selection.json`.
    pub output: Option<PathBuf>,
}

/// Runs the evaluation and writes the JSON report.
pub fn run_eval(command: &EvalCommand) -> CommandOutput {
    if command.runs == 0 || command.runs > 100 {
        return failure("runs must be from 1 through 100");
    }
    let config = match load_from_path(&command.config) {
        Ok(config) => config,
        Err(error) => return failure(&error.to_string()),
    };
    let runtime = match connect(&config) {
        Ok(runtime) => runtime,
        Err(error) => return failure(&report(&error)),
    };
    let sandbox = match sandbox_from(&config) {
        Ok(sandbox) => sandbox,
        Err(error) => return failure(&error),
    };
    let limits = match limits_from(&config) {
        Ok(limits) => limits.read_only(),
        Err(error) => return failure(&error),
    };
    if ToolRegistry::workspace().is_err() {
        return failure("workspace tool registry is unavailable");
    }
    let (ollama_version, model_digest) = identity(&config);
    let output = command.output.clone().unwrap_or_else(|| {
        PathBuf::from("target")
            .join("lca-eval")
            .join("tool-selection.json")
    });
    let plan = EvalPlan {
        runs: command.runs,
        preference: command.protocol,
        execution: EvalExecution::Live,
        identity: EvalIdentity {
            model: config.model().to_owned(),
            model_digest,
            ollama_version,
            temperature: None,
        },
    };
    let settings = TurnSettings {
        model: config.model().to_owned(),
        preference: command.protocol,
        max_tokens: config.generation_limit(),
        timeout: config.request_timeout(),
        context_tokens: config.context_window(),
        max_actions: usize::try_from(config.max_steps()).unwrap_or(lca_tools::MAX_ACTIONS),
    };
    let tokio_runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return failure(&format!("failed to start the runtime: {error}")),
    };
    let report = match tokio_runtime.block_on(evaluate_tool_selection(
        &runtime, &sandbox, &limits, &settings, &plan,
    )) {
        Ok(report) => report,
        Err(error) => return failure(&error.to_string()),
    };
    let body = serde_json::to_string_pretty(&report.to_json()).unwrap_or_else(|_| "{}".to_owned());
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return failure(&format!("failed to create the report directory: {error}"));
    }
    if let Err(error) = std::fs::write(&output, format!("{body}\n")) {
        return failure(&format!("failed to write the report: {error}"));
    }
    let mut stdout = report.summary();
    stdout.push_str("report: ");
    stdout.push_str(&output.display().to_string());
    stdout.push('\n');
    CommandOutput {
        exit_code: 0,
        stdout,
        stderr: String::new(),
    }
}

fn identity(config: &AgentConfig) -> (Option<String>, Option<String>) {
    let Ok(client) = HttpOllamaClient::new(config.endpoint(), config.connect_timeout()) else {
        return (None, None);
    };
    match client.describe_model(config.model()) {
        Ok(record) => (Some(record.version), record.digest),
        Err(_) => (None, None),
    }
}

fn connect(config: &AgentConfig) -> Result<OllamaModelRuntime, RuntimeError> {
    OllamaModelRuntime::connect(OllamaRuntimeConfig::new(
        config.endpoint(),
        config.connect_timeout(),
        config.request_timeout(),
    ))
}

/// Arguments for `lca eval agent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEvalCommand {
    /// Configuration file. It is loaded and not used as the evaluation workspace.
    pub config: PathBuf,
    /// Requests a live model run. This build refuses that path.
    pub live: bool,
    /// Report path. `None` uses `target/lca-eval/agent-runs.json`.
    pub output: Option<PathBuf>,
}

/// Runs the offline agent scenarios. A live request does not call the model and does not apply.
pub fn run_agent_eval(command: &AgentEvalCommand) -> CommandOutput {
    if let Err(error) = load_from_path(&command.config) {
        return failure(&error.to_string());
    }
    if command.live {
        let enabled = std::env::var("LCA_EVAL_LIVE").ok().as_deref() == Some("1");
        if !enabled {
            return failure("live agent evaluation requires LCA_EVAL_LIVE=1");
        }
        return failure(
            "live agent evaluation is fail-closed: this build does not apply patches and does not call the model from an evaluation",
        );
    }
    let tokio_runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return failure(&format!("failed to start the runtime: {error}")),
    };
    let report = match tokio_runtime.block_on(evaluate_agent_runs()) {
        Ok(report) => report,
        Err(error) => return failure(&error.to_string()),
    };
    let output = command.output.clone().unwrap_or_else(|| {
        PathBuf::from("target")
            .join("lca-eval")
            .join("agent-runs.json")
    });
    let body = serde_json::to_string_pretty(report.to_json()).unwrap_or_else(|_| "{}".to_owned());
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
        && let Err(error) = std::fs::create_dir_all(parent)
    {
        return failure(&format!("failed to create the report directory: {error}"));
    }
    if let Err(error) = std::fs::write(&output, format!("{body}\n")) {
        return failure(&format!("failed to write the report: {error}"));
    }
    let mut stdout = report.summary();
    stdout.push_str("report: ");
    stdout.push_str(&output.display().to_string());
    stdout.push('\n');
    CommandOutput {
        exit_code: 0,
        stdout,
        stderr: String::new(),
    }
}

fn failure(message: &str) -> CommandOutput {
    CommandOutput {
        exit_code: 1,
        stdout: String::new(),
        stderr: format!("lca: {message}\n"),
    }
}
