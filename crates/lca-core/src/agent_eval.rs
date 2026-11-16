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
use lca_tools::{
    ApplyFault, FsLimitValues, FsLimits, ProposalStore, ToolRegistry, WorkspaceSandbox,
};
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
    std::fs::write(root.join("alias-source.txt"), "HARDLINK_SENTINEL\n").map_err(|error| {
        RuntimeError::invalid(format!("eval workspace could not be seeded: {error}"))
    })?;
    std::fs::hard_link(root.join("alias-source.txt"), root.join("alias.txt")).map_err(|error| {
        RuntimeError::invalid(format!("eval hardlink could not be created: {error}"))
    })?;
    let reparse_outside = seed_reparse(&root)?;
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
    let evidence = apply_evidence();
    let _ = std::fs::remove_dir(root.join("link"));
    let _ = std::fs::remove_dir_all(&root);
    if let Some(outside) = reparse_outside {
        let _ = std::fs::remove_dir_all(outside);
    }
    let evidence = evidence?;
    if notes != b"alpha\n" {
        return Err(RuntimeError::invalid(
            "agent evaluation changed a workspace file",
        ));
    }
    let mut body = summarize(&runs, duration_ms);
    body["apply_evidence"] = evidence;
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
            id: "hardlink_alias",
            prompt: "Lies alias.txt.",
            steps: vec![action_doc(&[("read_file", json!({"path": "alias.txt"}))])],
            budgets: AgentBudgets::defaults(),
        },
        Case {
            id: "reparse_denied",
            prompt: "Lies link/secret.txt.",
            steps: vec![action_doc(&[(
                "read_file",
                json!({"path": "link/secret.txt"}),
            )])],
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
            "detail_kind": report.detail_kind(),
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

fn seed_reparse(root: &std::path::Path) -> Result<Option<PathBuf>, RuntimeError> {
    #[cfg(windows)]
    {
        let outside = root.with_file_name(format!(
            "{}-reparse-out",
            root.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("lca")
        ));
        std::fs::create_dir_all(&outside).map_err(|error| {
            RuntimeError::invalid(format!("reparse target could not be created: {error}"))
        })?;
        std::fs::write(outside.join("secret.txt"), "JUNCTION_SENTINEL\n").map_err(|error| {
            RuntimeError::invalid(format!("reparse target could not be seeded: {error}"))
        })?;
        let link = root.join("link");
        let output = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &outside.to_string_lossy(),
            ])
            .output()
            .map_err(|error| {
                RuntimeError::invalid(format!("junction could not be created: {error}"))
            })?;
        if !output.status.success() {
            let _ = std::fs::remove_dir_all(&outside);
            return Err(RuntimeError::invalid(format!(
                "junction was refused: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(Some(outside))
    }
    #[cfg(not(windows))]
    {
        let _ = root;
        Ok(None)
    }
}

fn apply_evidence() -> Result<Value, RuntimeError> {
    #[cfg(not(windows))]
    {
        return Ok(json!({"platform": "unsupported"}));
    }
    #[cfg(windows)]
    {
        let root = temp_dir();
        let state = temp_dir();
        let result = apply_evidence_windows(&root, &state);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&state);
        result
    }
}

#[cfg(windows)]
fn apply_evidence_windows(
    root: &std::path::Path,
    state: &std::path::Path,
) -> Result<Value, RuntimeError> {
    std::fs::write(root.join("notes.txt"), "alpha\n")
        .map_err(|error| RuntimeError::invalid(format!("evidence workspace: {error}")))?;
    let sandbox = WorkspaceSandbox::new(root)
        .map_err(|error| RuntimeError::invalid(format!("evidence sandbox: {error}")))?;
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
    let store = ProposalStore::open(state)
        .map_err(|error| RuntimeError::invalid(format!("evidence store: {error}")))?;
    let prepared = prepare_notes(&sandbox, &limits)?;
    let saved = store
        .save(&sandbox, &prepared)
        .map_err(|error| RuntimeError::invalid(format!("evidence save: {error}")))?;
    if !tamper_proposal(state)? {
        return Err(RuntimeError::invalid(
            "evidence proposal file was not found".to_owned(),
        ));
    }
    let tampered = store.show(&sandbox, &saved.id);
    let conflict_prepared = prepare_notes(&sandbox, &limits)?;
    std::fs::write(root.join("notes.txt"), "changed\n")
        .map_err(|error| RuntimeError::invalid(format!("evidence conflict seed: {error}")))?;
    let conflict_saved = store
        .save(&sandbox, &conflict_prepared)
        .map_err(|error| RuntimeError::invalid(format!("evidence conflict save: {error}")))?;
    let conflict_view = store
        .show(&sandbox, &conflict_saved.id)
        .map_err(|error| RuntimeError::invalid(format!("evidence conflict show: {error}")))?;
    let conflict = store.approve(
        &sandbox,
        &limits,
        &conflict_saved.id,
        &conflict_view.digest,
        &conflict_view.confirmation,
    );
    let conflict_bytes = std::fs::read(root.join("notes.txt")).unwrap_or_default();
    std::fs::write(root.join("notes.txt"), "alpha\n")
        .map_err(|error| RuntimeError::invalid(format!("evidence restore: {error}")))?;
    let fault_prepared = prepare_notes(&sandbox, &limits)?;
    let fault_saved = store
        .save(&sandbox, &fault_prepared)
        .map_err(|error| RuntimeError::invalid(format!("evidence fault save: {error}")))?;
    let fault_view = store
        .show(&sandbox, &fault_saved.id)
        .map_err(|error| RuntimeError::invalid(format!("evidence fault show: {error}")))?;
    let fault = store.approve_with(
        &sandbox,
        &limits,
        &fault_saved.id,
        &fault_view.digest,
        &fault_view.confirmation,
        ApplyFault::DuringReadback,
    );
    let after_fault = std::fs::read(root.join("notes.txt")).unwrap_or_default();
    let recovered = store
        .status(&sandbox, &fault_saved.id)
        .map_err(|error| RuntimeError::invalid(format!("evidence status: {error}")))?;
    let second = store.approve(
        &sandbox,
        &limits,
        &fault_saved.id,
        &fault_view.digest,
        &fault_view.confirmation,
    );
    let final_bytes = std::fs::read(root.join("notes.txt")).unwrap_or_default();
    if tampered.is_ok()
        || conflict.is_ok()
        || conflict_bytes != b"changed\n"
        || fault.is_ok()
        || after_fault != b"beta\n"
        || recovered.state != "applied"
        || second.is_ok()
        || final_bytes != b"beta\n"
    {
        return Err(RuntimeError::invalid(
            "apply evidence did not match the fault, conflict, or tamper checks".to_owned(),
        ));
    }
    Ok(json!({
        "platform": "windows",
        "tampered_proposal_rejected": true,
        "apply_conflict_kept_bytes": true,
        "fault_recovered_without_rewrite": true,
        "patches_applied_by_agent": 0,
    }))
}

#[cfg(windows)]
fn prepare_notes(
    sandbox: &WorkspaceSandbox,
    limits: &FsLimits,
) -> Result<lca_tools::PreparedPatch, RuntimeError> {
    use lca_tools::{
        ActionIdFactory, ActionSource, FsOutcome, execute_validated, propose_actions,
        validate_batch,
    };
    let patch = "--- a/notes.txt\n+++ b/notes.txt\n@@ -1,1 +1,1 @@\n-alpha\n+beta\n";
    let registry =
        ToolRegistry::workspace().map_err(|error| RuntimeError::invalid(error.to_string()))?;
    let proposed = propose_actions(
        &ActionIdFactory::new(),
        ActionSource::Native,
        [(
            "apply_patch".to_owned(),
            json!({"path": "notes.txt", "patch": patch}),
        )],
    );
    let batch = validate_batch(&registry, &proposed)
        .map_err(|error| RuntimeError::invalid(error.to_string()))?;
    let outcome = execute_validated(&batch.actions()[0], sandbox, limits)
        .map_err(|error| RuntimeError::invalid(error.to_string()))?;
    match outcome {
        FsOutcome::Prepared(prepared) => Ok(*prepared),
        _ => Err(RuntimeError::invalid(
            "evidence prepare did not return a patch".to_owned(),
        )),
    }
}

#[cfg(windows)]
fn tamper_proposal(state: &std::path::Path) -> Result<bool, RuntimeError> {
    let mut flipped = false;
    let proposals = state.join("proposals");
    let workspaces = std::fs::read_dir(&proposals).map_err(|error| {
        RuntimeError::invalid(format!("evidence proposals could not be listed: {error}"))
    })?;
    for workspace in workspaces.flatten() {
        let files = match std::fs::read_dir(workspace.path()) {
            Ok(files) => files,
            Err(_) => continue,
        };
        for file in files.flatten() {
            let path = file.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("lcap") {
                continue;
            }
            let mut bytes = std::fs::read(&path).map_err(|error| {
                RuntimeError::invalid(format!("evidence proposal could not be read: {error}"))
            })?;
            if let Some(last) = bytes.last_mut() {
                *last ^= 0x5a;
            }
            std::fs::write(&path, &bytes).map_err(|error| {
                RuntimeError::invalid(format!("evidence proposal could not be changed: {error}"))
            })?;
            flipped = true;
        }
    }
    Ok(flipped)
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
        assert!(!json.to_string().contains("HARDLINK_SENTINEL"));
        assert!(!json.to_string().contains("JUNCTION_SENTINEL"));
        assert!(!json.to_string().contains("beta\n"));
        assert_eq!(json["patches_applied"], 0);
        #[cfg(windows)]
        {
            assert_eq!(
                json["apply_evidence"]["fault_recovered_without_rewrite"],
                true
            );
            assert_eq!(json["apply_evidence"]["tampered_proposal_rejected"], true);
            assert_eq!(json["apply_evidence"]["apply_conflict_kept_bytes"], true);
        }
        let cases = json["cases"].as_array().expect("cases");
        let field = |id: &str, key: &str| {
            cases
                .iter()
                .find(|case| case["id"] == id)
                .and_then(|case| case[key].as_str())
                .unwrap_or("")
                .to_owned()
        };
        assert_eq!(field("hardlink_alias", "detail_kind"), "hardlink_denied");
        assert_eq!(field("reparse_denied", "detail_kind"), "reparse_denied");
        assert_eq!(field("prepared_patch", "stop_reason"), "prepared_patch");
    }
}
