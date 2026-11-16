//! `lca agent execute` runs a bounded sequence of model turns.
//!
//! The protocol is selected once. Read tools may run. `apply_patch` is prepared and not
//! written. The approval binding is process-local, so this command does not print a
//! confirmation line and does not accept a grant. A failure or a spent budget does not
//! start another protocol.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use lca_config::{AgentConfig, load_from_path};
use lca_core::{
    AgentBudgets, BoundedAgentController, ExecutedAction, LoopError, LoopSettings, RunReport,
    RunStatus, StopReason,
};
use lca_model_runtime::{ProtocolPreference, RuntimeError, report};
use lca_ollama::{OllamaModelRuntime, OllamaRuntimeConfig};
use lca_tools::FsOutcome;
use serde_json::json;

use crate::CommandOutput;
use crate::publish::persist_prepared;
use crate::tools_cmd::{limits_from, sandbox_from};

/// Arguments for `lca agent execute`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteCommand {
    /// Configuration file selected by `--config`, or `lca.toml`.
    pub config: PathBuf,
    /// Requested protocol.
    pub protocol: ProtocolPreference,
    /// Override for the model-turn budget.
    pub max_turns: Option<u32>,
    /// Override for the per-run action budget.
    pub max_actions: Option<u32>,
    /// Whether stdout is one JSON object.
    pub json: bool,
    /// User task, before trimming.
    pub prompt: String,
}

/// Loads configuration, runs the bounded controller, and renders a buffered result.
pub fn run_execute(command: &ExecuteCommand) -> CommandOutput {
    if command.prompt.trim().is_empty() {
        return failure("prompt must not be empty");
    }
    let config = match load_from_path(&command.config) {
        Ok(config) => config,
        Err(error) => return failure(&error.to_string()),
    };
    let budgets = match budgets_from(&config, command) {
        Ok(budgets) => budgets,
        Err(error) => return failure(&error),
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
    let registry = match lca_tools::ToolRegistry::workspace() {
        Ok(registry) => registry,
        Err(error) => return failure(&error.to_string()),
    };
    let stored = sandbox.clone();
    let controller = BoundedAgentController::new(
        registry,
        sandbox,
        limits,
        LoopSettings {
            model: config.model().to_owned(),
            preference: command.protocol,
            max_tokens: config.generation_limit(),
            timeout: config.request_timeout(),
            context_tokens: config.context_window(),
            budgets,
        },
    );
    let tokio_runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return failure(&format!("failed to start the runtime: {error}")),
    };
    let cancelled = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let prompt = command.prompt.clone();
    let report = tokio_runtime.block_on(async move {
        let flag = Arc::clone(&cancelled);
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                flag.store(true, Ordering::SeqCst);
            }
        });
        let elapsed = move || started.elapsed();
        controller
            .run(&runtime, &prompt, &elapsed, cancelled.as_ref())
            .await
    });
    match report {
        Ok(report) => {
            let ids = match persist_prepared(&stored, &prepared_patches(&report)) {
                Ok(ids) => ids,
                Err(error) => return failure(&error),
            };
            render(&report, &ids, command.json)
        }
        Err(error) => failure(&explain_loop(&error)),
    }
}

fn prepared_patches(report: &RunReport) -> Vec<&lca_tools::PreparedPatch> {
    report
        .turns()
        .iter()
        .flat_map(|turn| turn.actions())
        .filter_map(|action| match action.outcome() {
            FsOutcome::Prepared(prepared) => Some(prepared.as_ref()),
            _ => None,
        })
        .collect()
}

fn budgets_from(config: &AgentConfig, command: &ExecuteCommand) -> Result<AgentBudgets, String> {
    let turns = command.max_turns.unwrap_or(config.agent_max_turns());
    let per_turn = usize::try_from(config.agent_max_actions_per_turn())
        .map_err(|_| "actions per turn do not fit".to_owned())?;
    let per_run = usize::try_from(
        command
            .max_actions
            .unwrap_or(config.agent_max_actions_per_run()),
    )
    .map_err(|_| "actions per run do not fit".to_owned())?;
    let result_bytes = usize::try_from(config.agent_max_tool_result_bytes())
        .map_err(|_| "tool result budget does not fit".to_owned())?;
    let history_bytes = usize::try_from(config.agent_max_history_bytes())
        .map_err(|_| "history budget does not fit".to_owned())?;
    AgentBudgets::try_new(
        turns,
        per_turn,
        per_run,
        result_bytes,
        history_bytes,
        config.agent_timeout(),
    )
    .map_err(|error| error.to_string())
}

fn connect(config: &AgentConfig) -> Result<OllamaModelRuntime, RuntimeError> {
    OllamaModelRuntime::connect(OllamaRuntimeConfig::new(
        config.endpoint(),
        config.connect_timeout(),
        config.request_timeout(),
    ))
}

fn render(report: &RunReport, proposal_ids: &[String], json_output: bool) -> CommandOutput {
    let stdout = if json_output {
        render_json(report, proposal_ids)
    } else {
        render_text(report, proposal_ids)
    };
    let failed = !matches!(report.status(), RunStatus::Completed);
    CommandOutput {
        exit_code: if failed { 1 } else { 0 },
        stdout,
        stderr: if failed {
            format!(
                "lca: {}\n",
                report.detail().unwrap_or(report.stop_reason().as_str())
            )
        } else {
            String::new()
        },
    }
}

fn render_text(report: &RunReport, proposal_ids: &[String]) -> String {
    let mut out = String::new();
    let mut ids = proposal_ids.iter();
    push(
        &mut out,
        "protocol",
        report
            .protocol()
            .map(|protocol| protocol.as_str())
            .unwrap_or("unavailable"),
    );
    push(&mut out, "model", report.model());
    push(
        &mut out,
        "profile_version",
        &report.profile_version().to_string(),
    );
    push(&mut out, "preferred_protocol", report.preferred_protocol());
    push(&mut out, "status", report.status().as_str());
    push(&mut out, "stop_reason", report.stop_reason().as_str());
    push(&mut out, "model_turns", &report.model_turns().to_string());
    push(&mut out, "tool_actions", &report.tool_actions().to_string());
    for turn in report.turns() {
        out.push('\n');
        push(&mut out, "turn", &turn.index().to_string());
        if turn.actions().is_empty()
            && let Some(answer) = turn.final_answer()
        {
            out.push_str("final_answer:\n");
            out.push_str(answer);
            if !answer.is_empty() && !answer.ends_with('\n') {
                out.push('\n');
            }
        }
        for action in turn.actions() {
            render_action(&mut out, action, &mut ids);
        }
    }
    if report.stop_reason() == StopReason::FinalAnswer && report.turns().is_empty() {
        out.push_str("final_answer:\n");
        out.push_str(report.final_answer());
        if !report.final_answer().ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn render_action<'a>(
    out: &mut String,
    action: &ExecutedAction,
    ids: &mut impl Iterator<Item = &'a String>,
) {
    push(out, "tool", action.tool());
    match action.outcome() {
        FsOutcome::NotExecuted { .. } => push(out, "result", "not_executed"),
        FsOutcome::Listed(list) => {
            push(out, "result", "listed");
            push(out, "path", &list.path);
            for entry in &list.entries {
                out.push_str(&format!("{}: {}\n", entry.kind, entry.path));
            }
        }
        FsOutcome::Read(file) => {
            push(out, "result", "read");
            push(out, "path", &file.path);
            out.push_str("---\n");
            out.push_str(&file.content);
            if !file.content.is_empty() && !file.content.ends_with('\n') {
                out.push('\n');
            }
        }
        FsOutcome::Searched(result) => {
            push(out, "result", "searched");
            for hit in &result.matches {
                out.push_str(&format!("match: {}:{}:{}\n", hit.path, hit.line, hit.text));
            }
        }
        FsOutcome::Prepared(prepared) => {
            push(out, "result", "prepared");
            push(out, "path", prepared.relative_path());
            push(out, "applied", "false");
            push(out, "approval", "unavailable");
            if let Some(id) = ids.next() {
                push(out, "proposal_id", id);
                push(out, "proposal_state", "prepared");
            }
            out.push_str("diff:\n");
            out.push_str(prepared.diff());
            if !prepared.diff().ends_with('\n') {
                out.push('\n');
            }
        }
    }
}

fn render_json(report: &RunReport, proposal_ids: &[String]) -> String {
    let mut ids = proposal_ids.iter();
    let turns = report
        .turns()
        .iter()
        .map(|turn| {
            json!({
                "turn": turn.index(),
                "final_answer": turn.final_answer(),
                "actions": turn.actions().iter().map(|action| {
                    let mut value = json!({
                        "tool": action.tool(),
                        "result": result_name(action),
                    });
                    if matches!(action.outcome(), FsOutcome::Prepared(_))
                        && let Some(id) = ids.next()
                    {
                        value["proposal_id"] = json!(id);
                        value["proposal_state"] = json!("prepared");
                    }
                    value
                }).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let value = json!({
        "protocol": report.protocol().map(|protocol| protocol.as_str()),
        "model": report.model(),
        "profile_version": report.profile_version(),
        "preferred_protocol": report.preferred_protocol(),
        "status": report.status().as_str(),
        "stop_reason": report.stop_reason().as_str(),
        "model_turns": report.model_turns(),
        "tool_actions": report.tool_actions(),
        "final_answer": report.final_answer(),
        "turns": turns,
    });
    format!("{value}\n")
}

fn result_name(action: &ExecutedAction) -> &'static str {
    match action.outcome() {
        FsOutcome::NotExecuted { .. } => "not_executed",
        FsOutcome::Listed(_) => "listed",
        FsOutcome::Read(_) => "read",
        FsOutcome::Searched(_) => "searched",
        FsOutcome::Prepared(_) => "prepared",
    }
}

fn explain_loop(error: &LoopError) -> String {
    error.to_string()
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
