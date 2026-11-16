//! Offline evaluation of complete bounded runs.
//!
//! The scripted runtime never calls Ollama. A prepared patch is not applied. Live use of
//! this module is the caller's choice; this function itself does not open a socket.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use lca_model_runtime::{
    CapabilityParts, CapabilityStatus, GenerationRequest, GenerationResponse, GenerationStream,
    ModelCapabilities, ModelRuntime, ProtocolPreference, RuntimeError,
};
use lca_tools::{FsLimitValues, FsLimits, ToolRegistry, WorkspaceSandbox};
use serde_json::{Value, json};

use crate::bounded::{
    AgentBudgets, BoundedAgentController, LoopSettings, RunReport, RunStatus, StopReason,
};

/// Counts from one offline agent-run evaluation. File bytes are not stored.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentEvalReport {
    body: Value,
}

impl AgentEvalReport {
    /// JSON document. It records counts and durations, not file contents.
    #[must_use]
    pub fn to_json(&self) -> &Value {
        &self.body
    }

    /// Compact terminal summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut out = String::new();
        for key in [
            "execution",
            "successful_runs",
            "protocol_errors",
            "tool_errors",
            "invalid_arguments",
            "budget_stops",
            "policy_denials",
            "unnecessary_tool_calls",
            "prepared_patches",
            "patches_applied",
            "average_model_turns",
            "duration_ms",
        ] {
            if let Some(value) = self.body.get(key) {
                out.push_str(key);
                out.push_str(": ");
                let rendered = value.to_string();
                out.push_str(rendered.trim_matches('"'));
                out.push('\n');
            }
        }
        out
    }
}

/// Runs the fixed scenarios against a scripted runtime in a temporary workspace.
///
/// The temporary files are removed before the function returns. No patch is applied.
pub async fn evaluate_agent_runs() -> Result<AgentEvalReport, RuntimeError> {
    let root = temp_dir();
    std::fs::write(root.join("notes.txt"), "alpha\n").map_err(|error| {
        RuntimeError::invalid(format!("eval workspace could not be seeded: {error}"))
    })?;
    std::fs::write(root.join("lca.toml"), "SENTINEL_SECRET\n").map_err(|error| {
        RuntimeError::invalid(format!("eval workspace could not be seeded: {error}"))
    })?;
    let sandbox = WorkspaceSandbox::new(&root)
        .map_err(|error| RuntimeError::invalid(format!("eval sandbox was rejected: {error}")))?;
    let limits = FsLimits::try_new(FsLimitValues {
        read_enabled: true,
        write_enabled: true,
        max_file_size_bytes: 1024 * 1024,
        max_response_bytes: 256 * 1024,
        max_directory_entries: 100,
        max_search_matches: 20,
        max_search_files: 100,
        max_search_total_bytes: 1024 * 1024,
    })
    .map_err(|error| RuntimeError::invalid(error.to_string()))?;
    let started = Instant::now();
    let mut runs = Vec::new();
    for case in cases() {
        let report = run_case(&sandbox, &limits, &case).await?;
        runs.push((case, report));
    }
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let notes = std::fs::read(root.join("notes.txt")).unwrap_or_default();
    let secret = std::fs::read_to_string(root.join("lca.toml")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&root);
    if notes != b"alpha\n" {
        return Err(RuntimeError::invalid(
            "agent evaluation changed a workspace file",
        ));
    }
    let body = summarize(&runs, duration_ms);
    let rendered = body.to_string();
    if rendered.contains("SENTINEL_SECRET") || secret.is_empty() {
        return Err(RuntimeError::invalid(
            "agent evaluation exposed or dropped the privacy sentinel",
        ));
    }
    Ok(AgentEvalReport { body })
}

struct Case {
    id: &'static str,
    prompt: &'static str,
    steps: Vec<String>,
    budgets: AgentBudgets,
}

fn cases() -> Vec<Case> {
    let patch = "--- a/notes.txt\n+++ b/notes.txt\n@@ -1,1 +1,1 @@\n-alpha\n+beta\n";
    vec![
        Case {
            id: "knowledge",
            prompt: "Erkläre Ownership.",
            steps: vec![final_doc(
                "Rust Ownership regelt die eindeutige Zuständigkeit für Werte.",
            )],
            budgets: AgentBudgets::defaults(),
        },
        Case {
            id: "search_read_final",
            prompt: "Suche und lies notes.txt.",
            steps: vec![
                action_doc(&[("search_files", json!({"query": "alpha", "path": "."}))]),
                action_doc(&[("read_file", json!({"path": "notes.txt"}))]),
                final_doc("Die Datei enthält alpha."),
            ],
            budgets: AgentBudgets::defaults(),
        },
        Case {
            id: "multiple_reads",
            prompt: "Lies notes.txt zweimal.",
            steps: vec![
                action_doc(&[
                    ("read_file", json!({"path": "notes.txt"})),
                    ("read_file", json!({"path": "notes.txt"})),
                ]),
                final_doc("Zweimal gelesen."),
            ],
            budgets: AgentBudgets::defaults(),
        },
        Case {
            id: "privacy_denial",
            prompt: "Lies lca.toml.",
            steps: vec![action_doc(&[("read_file", json!({"path": "lca.toml"}))])],
            budgets: AgentBudgets::defaults(),
        },
        Case {
            id: "prepared_patch",
            prompt: "Ändere notes.txt.",
            steps: vec![action_doc(&[(
                "apply_patch",
                json!({"path": "notes.txt", "patch": patch}),
            )])],
            budgets: AgentBudgets::defaults(),
        },
        Case {
            id: "budget_exhaustion",
            prompt: "Lies und fasse zusammen.",
            steps: vec![
                action_doc(&[("read_file", json!({"path": "notes.txt"}))]),
                final_doc("must not run"),
            ],
            budgets: AgentBudgets::try_new(1, 4, 4, 64 * 1024, 256 * 1024, Duration::from_secs(30))
                .unwrap_or_else(|_| AgentBudgets::defaults()),
        },
        Case {
            id: "invalid_json",
            prompt: "Antworte.",
            steps: vec!["not json".to_owned()],
            budgets: AgentBudgets::defaults(),
        },
        Case {
            id: "invalid_arguments",
            prompt: "Lies etwas.",
            steps: vec![action_doc(&[("read_file", json!({}))])],
            budgets: AgentBudgets::defaults(),
        },
    ]
}

fn action_doc(actions: &[(&str, Value)]) -> String {
    let actions = actions
        .iter()
        .map(|(tool, arguments)| json!({"tool": tool, "arguments": arguments}))
        .collect::<Vec<_>>();
    json!({"protocol_version": 2, "actions": actions}).to_string()
}

fn final_doc(answer: &str) -> String {
    json!({"protocol_version": 2, "actions": [], "final_answer": answer}).to_string()
}

async fn run_case(
    sandbox: &WorkspaceSandbox,
    limits: &FsLimits,
    case: &Case,
) -> Result<RunReport, RuntimeError> {
    let registry =
        ToolRegistry::workspace().map_err(|error| RuntimeError::invalid(error.to_string()))?;
    let controller = BoundedAgentController::new(
        registry,
        sandbox.clone(),
        limits.clone(),
        LoopSettings {
            model: "lca-eval".to_owned(),
            preference: ProtocolPreference::StructuredJson,
            max_tokens: 128,
            timeout: Duration::from_secs(5),
            context_tokens: 2048,
            budgets: case.budgets.clone(),
        },
    );
    let runtime = Scripted {
        steps: Mutex::new(case.steps.clone()),
        generates: AtomicUsize::new(0),
    };
    let cancelled = AtomicBool::new(false);
    let elapsed = || Duration::ZERO;
    controller
        .run(&runtime, case.prompt, &elapsed, &cancelled)
        .await
        .map_err(|error| RuntimeError::invalid(error.to_string()))
}

fn summarize(runs: &[(Case, RunReport)], duration_ms: u64) -> Value {
    let mut successful = 0u32;
    let mut protocol_errors = 0u32;
    let mut tool_errors = 0u32;
    let mut invalid_arguments = 0u32;
    let mut budget_stops = 0u32;
    let mut policy_denials = 0u32;
    let mut unnecessary = 0u32;
    let mut prepared = 0u32;
    let mut turns = 0u32;
    let mut case_rows = Vec::new();
    for (case, report) in runs {
        turns += report.model_turns();
        if report.status() == RunStatus::Completed {
            successful += 1;
        }
        match report.stop_reason() {
            StopReason::ProtocolError => protocol_errors += 1,
            StopReason::ToolError => tool_errors += 1,
            StopReason::ValidationError => invalid_arguments += 1,
            StopReason::TurnBudget
            | StopReason::ActionBudget
            | StopReason::ResultBudget
            | StopReason::HistoryBudget
            | StopReason::Timeout => budget_stops += 1,
            StopReason::PreparedPatch => prepared += 1,
            _ => {}
        }
        if report.detail_kind() == Some("privacy_denied") {
            policy_denials += 1;
        }
        if case.id == "knowledge" && report.tool_actions() > 0 {
            unnecessary += report.tool_actions() as u32;
        }
        case_rows.push(json!({
            "id": case.id,
            "status": report.status().as_str(),
            "stop_reason": report.stop_reason().as_str(),
            "model_turns": report.model_turns(),
            "tool_actions": report.tool_actions(),
        }));
    }
    let average = if runs.is_empty() {
        0.0
    } else {
        f64::from(turns) / runs.len() as f64
    };
    json!({
        "execution": "mock",
        "write_applied": false,
        "successful_runs": successful,
        "protocol_errors": protocol_errors,
        "tool_errors": tool_errors,
        "invalid_arguments": invalid_arguments,
        "budget_stops": budget_stops,
        "policy_denials": policy_denials,
        "unnecessary_tool_calls": unnecessary,
        "prepared_patches": prepared,
        "patches_applied": 0,
        "average_model_turns": (average * 100.0).round() / 100.0,
        "duration_ms": duration_ms,
        "cases": case_rows,
    })
}

struct Scripted {
    steps: Mutex<Vec<String>>,
    generates: AtomicUsize,
}

#[async_trait]
impl ModelRuntime for Scripted {
    async fn generate(
        &self,
        request: GenerationRequest,
    ) -> Result<GenerationResponse, RuntimeError> {
        request.validate()?;
        self.generates.fetch_add(1, Ordering::SeqCst);
        let mut steps = self
            .steps
            .lock()
            .map_err(|_| RuntimeError::invalid("eval script lock"))?;
        if steps.is_empty() {
            return Err(RuntimeError::protocol("eval script exhausted"));
        }
        let text = steps.remove(0);
        Ok(GenerationResponse::complete(
            "lca-eval", text, None, None, None,
        ))
    }

    async fn generate_stream(
        &self,
        _request: GenerationRequest,
    ) -> Result<GenerationStream, RuntimeError> {
        Err(RuntimeError::invalid("agent evaluation does not stream"))
    }

    async fn capabilities(&self, model: &str) -> Result<ModelCapabilities, RuntimeError> {
        Ok(ModelCapabilities::from_parts(
            model,
            CapabilityParts {
                chat: CapabilityStatus::Confirmed,
                tools: CapabilityStatus::Confirmed,
                json_mode: CapabilityStatus::Confirmed,
                ..CapabilityParts::default()
            },
        ))
    }
}

fn temp_dir() -> PathBuf {
    static NEXT: OnceLock<Mutex<u64>> = OnceLock::new();
    let counter = NEXT.get_or_init(|| Mutex::new(0));
    let id = {
        let mut value = counter.lock().unwrap_or_else(|error| error.into_inner());
        *value = value.saturating_add(1);
        *value
    };
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("lca-agent-eval-{nanos}-{id}"));
    let _ = std::fs::create_dir_all(&path);
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn offline_runs_cover_the_scenarios_and_apply_nothing() {
        let report = evaluate_agent_runs().await.expect("eval");
        let json = report.to_json();
        assert_eq!(json["execution"], "mock");
        assert_eq!(json["patches_applied"], 0);
        assert_eq!(json["prepared_patches"], 1);
        assert_eq!(json["policy_denials"], 1);
        assert_eq!(json["protocol_errors"], 1);
        assert_eq!(json["invalid_arguments"], 1);
        assert_eq!(json["budget_stops"], 1);
        assert!(json["successful_runs"].as_u64().unwrap_or(0) >= 4);
        assert_eq!(json["unnecessary_tool_calls"], 0);
        assert!(!json.to_string().contains("SENTINEL_SECRET"));
        assert!(!json.to_string().contains("beta\n"));
    }
}
