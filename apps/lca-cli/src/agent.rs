//! `lca agent run` performs one model turn and at most one tool batch.
//!
//! The command loads configuration, selects a protocol, and calls the model once.
//! Read tools run after validation. `apply_patch` is prepared and not written.
//! A model or tool failure is not retried.

use std::path::PathBuf;
use std::time::SystemTime;

use lca_config::{AgentConfig, load_from_path};
use lca_core::{ExecutedAction, SingleTurnAgentController, TurnError, TurnReport, TurnSettings};
use lca_model_runtime::{ProtocolPreference, RuntimeError, report};
use lca_ollama::{OllamaModelRuntime, OllamaRuntimeConfig};
use lca_tools::{FsOutcome, ToolRegistry};

use crate::CommandOutput;
use crate::tools_cmd::{limits_from, sandbox_from};

/// Arguments for `lca agent run`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCommand {
    /// Configuration file selected by `--config`, or `lca.toml`.
    pub config: PathBuf,
    /// Requested protocol.
    pub protocol: ProtocolPreference,
    /// User task, before trimming.
    pub prompt: String,
}

/// Loads configuration, runs one turn, and renders a buffered result.
pub fn run_agent(command: &AgentCommand) -> CommandOutput {
    if command.prompt.trim().is_empty() {
        return failure("prompt must not be empty");
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
        Ok(limits) => limits,
        Err(error) => return failure(&error),
    };
    let registry = match ToolRegistry::workspace() {
        Ok(registry) => registry,
        Err(error) => return failure(&error.to_string()),
    };
    let max_actions = usize::try_from(config.max_steps()).unwrap_or(lca_tools::MAX_ACTIONS);
    let controller = match SingleTurnAgentController::new(
        registry,
        sandbox,
        limits,
        TurnSettings {
            model: config.model().to_owned(),
            preference: command.protocol,
            max_tokens: config.generation_limit(),
            timeout: config.request_timeout(),
            context_tokens: config.context_window(),
            max_actions,
        },
    ) {
        Ok(controller) => controller,
        Err(error) => return failure(&explain(&error)),
    };
    let tokio_runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return failure(&format!("failed to start the runtime: {error}")),
    };
    match tokio_runtime.block_on(controller.run(&runtime, &command.prompt, SystemTime::now())) {
        Ok(report) => render_report(&report),
        Err(error) => render_failure(&error),
    }
}

fn connect(config: &AgentConfig) -> Result<OllamaModelRuntime, RuntimeError> {
    OllamaModelRuntime::connect(OllamaRuntimeConfig::new(
        config.endpoint(),
        config.connect_timeout(),
        config.request_timeout(),
    ))
}

fn render_report(report: &TurnReport) -> CommandOutput {
    let mut stdout = String::new();
    push_header(
        &mut stdout,
        report.protocol().as_str(),
        report.model_calls(),
        report.actions().len(),
    );
    push(
        &mut stdout,
        "response_class",
        report.response_class().as_str(),
    );
    if let Some(diagnostic) = report.diagnostic() {
        push(&mut stdout, "diagnostic", diagnostic);
    };
    for action in report.actions() {
        render_action(&mut stdout, action);
    }
    push_model_text(&mut stdout, report.text());
    CommandOutput {
        exit_code: 0,
        stdout,
        stderr: String::new(),
    }
}

fn render_failure(error: &TurnError) -> CommandOutput {
    let mut stdout = String::new();
    for action in error.prior_actions() {
        render_action(&mut stdout, action);
    }
    CommandOutput {
        exit_code: 1,
        stdout,
        stderr: format!("lca: {}\n", explain(error)),
    }
}

fn explain(error: &TurnError) -> String {
    match error {
        TurnError::Runtime(error) => report(error),
        other => other.to_string(),
    }
}

fn push_header(out: &mut String, protocol: &str, model_calls: u32, actions: usize) {
    push(out, "protocol", protocol);
    push(out, "model_calls", &model_calls.to_string());
    push(out, "actions", &actions.to_string());
}

fn render_action(out: &mut String, action: &ExecutedAction) {
    push(out, "action", &action.id().to_string());
    push(out, "tool", action.tool());
    push(out, "source", action.source().as_str());
    match action.outcome() {
        FsOutcome::NotExecuted { .. } => push(out, "result", "not_executed"),
        FsOutcome::Listed(list) => {
            push(out, "result", "listed");
            push(out, "path", &list.path);
            push(out, "truncated", bool_text(list.truncated));
            for entry in &list.entries {
                match entry.kind.as_str() {
                    "file" => {
                        let size = entry.size.unwrap_or(0);
                        out.push_str(&format!("file: {} size={size}\n", entry.path));
                    }
                    "directory" => out.push_str(&format!("directory: {}\n", entry.path)),
                    "reparse" => out.push_str(&format!("reparse: {}\n", entry.path)),
                    _ => {
                        let message = entry.error.as_deref().unwrap_or("unavailable");
                        out.push_str(&format!("error: {} {message}\n", entry.path));
                    }
                }
            }
        }
        FsOutcome::Read(file) => {
            push(out, "result", "read");
            push(out, "path", &file.path);
            push(out, "truncated", bool_text(file.truncated));
            push(out, "bytes", &file.file_bytes.to_string());
            out.push_str("---\n");
            out.push_str(&file.content);
            if !file.content.is_empty() && !file.content.ends_with('\n') {
                out.push('\n');
            }
        }
        FsOutcome::Searched(result) => {
            push(out, "result", "searched");
            push(out, "truncated", bool_text(result.truncated));
            push(out, "files_scanned", &result.files_scanned.to_string());
            push(out, "skipped", &result.skipped.to_string());
            for hit in &result.matches {
                out.push_str(&format!("match: {}:{}:{}\n", hit.path, hit.line, hit.text));
            }
        }
        FsOutcome::Prepared(prepared) => {
            push(out, "result", "prepared");
            push(out, "path", prepared.relative_path());
            push(out, "approval", "required");
            push(out, "applied", "false");
            push(out, "action_id", &prepared.action_id().to_string());
            push(out, "line_ending", prepared.line_ending());
            push(out, "original_hash", &prepared.original_hash_hex());
            push(out, "new_hash", &prepared.new_hash_hex());
            push(out, "confirmation", &prepared.confirmation_line());
            out.push_str("diff:\n");
            out.push_str(prepared.diff());
            if !prepared.diff().ends_with('\n') {
                out.push('\n');
            }
        }
    }
}

fn push_model_text(out: &mut String, text: &str) {
    if text.is_empty() {
        return;
    }
    push(out, "model_text_bytes", &text.len().to_string());
    out.push_str("---\n");
    out.push_str(text);
    if !text.ends_with('\n') {
        out.push('\n');
    }
}

fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn push(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(": ");
    out.push_str(value);
    out.push('\n');
}

fn failure(message: &str) -> CommandOutput {
    CommandOutput {
        exit_code: 1,
        stdout: String::new(),
        stderr: format!("lca: {message}\n"),
    }
}
