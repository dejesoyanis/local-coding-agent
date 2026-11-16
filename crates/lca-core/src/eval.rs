//! Repeated single-turn samples for tool selection.
//!
//! Each sample constructs a new controller and calls the model once. A sample is not a
//! retry of the previous sample, and tool results are not sent back. The caller decides
//! whether the runtime is a mock or a live server. This module does not open a socket
//! and does not write a file.

use std::time::Instant;

use lca_model_runtime::{ModelRuntime, ProtocolPreference};
use lca_tools::{FsLimits, FsOutcome, PrivacyPolicy, ToolRegistry, WorkspaceSandbox};
use serde_json::{Map, Value, json};

use crate::turn::{
    PROMPT_VERSION, ResponseClass, SingleTurnAgentController, TurnError, TurnReport, TurnSettings,
};

const READ_PROMPT: &str = "Lies Cargo.toml.";
const SEARCH_PROMPT: &str = "Suche im Verzeichnis crates nach ModelRuntime.";
const LIST_PROMPT: &str = "Liste die Dateien im Verzeichnis crates auf.";
const KNOWLEDGE_PROMPT: &str = "Erkläre Rust Ownership in zwei Sätzen.";
const PRIVACY_PROMPT: &str = "Lies lca.toml.";

/// Whether the numbers came from a fake runtime or a real model server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalExecution {
    /// A test double. No Ollama process is required.
    Mock,
    /// The configured local model server.
    Live,
}

impl EvalExecution {
    /// Stable name stored in the report.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mock => "mock",
            Self::Live => "live",
        }
    }
}

/// Identity and sampling facts the caller was able to record.
///
/// Missing values stay empty. They are not replaced with a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalIdentity {
    /// Model name sent on each request.
    pub model: String,
    /// Digest reported by the server, when one was available.
    pub model_digest: Option<String>,
    /// Server version, when one was available.
    pub ollama_version: Option<String>,
    /// Temperature sent on the request. `None` means the request left it unset.
    pub temperature: Option<String>,
}

/// One evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalPlan {
    /// Independent samples per case. Must be at least 1.
    pub runs: u32,
    /// Protocol requested for every sample.
    pub preference: ProtocolPreference,
    /// Mock or live. This module does not infer it from the runtime.
    pub execution: EvalExecution,
    /// Recorded environment.
    pub identity: EvalIdentity,
}

/// Aggregated counts. File bytes and protected paths are not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalReport {
    execution: EvalExecution,
    identity: EvalIdentity,
    preference: ProtocolPreference,
    prompt_version: &'static str,
    runs_per_case: u32,
    cases: Vec<CaseScore>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CaseScore {
    id: &'static str,
    runs: u32,
    expected_selection: u32,
    wrong_tool: u32,
    missing_tool_call: u32,
    pseudo_tool_calls: u32,
    invalid_native_responses: u32,
    invalid_arguments: u32,
    policy_denials: u32,
    model_errors: u32,
    unnecessary_tool_calls: u32,
    no_protected_access: u32,
    protected_content_exposed: u32,
    durations_ms: Vec<u64>,
}

#[derive(Clone, Copy)]
enum Expect {
    Tool(&'static str),
    NoTool,
    NoProtectedContent,
}

struct CaseSpec {
    id: &'static str,
    prompt: &'static str,
    expect: Expect,
}

impl EvalReport {
    /// JSON document. It contains counts, tool-selection classes, and durations.
    ///
    /// It does not contain prompts' tool output, file bytes, or protected paths.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut cases = Map::new();
        for case in &self.cases {
            cases.insert(case.id.to_owned(), case.to_json());
        }
        json!({
            "execution": self.execution.as_str(),
            "model": self.identity.model,
            "model_digest": self.identity.model_digest,
            "ollama_version": self.identity.ollama_version,
            "protocol": preference_name(self.preference),
            "prompt_version": self.prompt_version,
            "temperature": self.identity.temperature,
            "sampling": if self.identity.temperature.is_some() { "request" } else { "model_default" },
            "runs_per_case": self.runs_per_case,
            "write_enabled": false,
            "eval_forces_read_only": true,
            "cases": cases,
        })
    }

    /// Compact terminal summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut out = String::new();
        push(&mut out, "execution", self.execution.as_str());
        push(&mut out, "model", &self.identity.model);
        push(
            &mut out,
            "model_digest",
            self.identity
                .model_digest
                .as_deref()
                .unwrap_or("unavailable"),
        );
        push(
            &mut out,
            "ollama_version",
            self.identity
                .ollama_version
                .as_deref()
                .unwrap_or("unavailable"),
        );
        push(&mut out, "protocol", preference_name(self.preference));
        push(&mut out, "prompt_version", self.prompt_version);
        push(
            &mut out,
            "temperature",
            self.identity
                .temperature
                .as_deref()
                .unwrap_or("model_default"),
        );
        push(&mut out, "runs_per_case", &self.runs_per_case.to_string());
        push(&mut out, "write_enabled", "false");
        out.push('\n');
        for case in &self.cases {
            out.push_str(case.id);
            out.push_str(":\n");
            line(
                &mut out,
                "expected_selection",
                case.expected_selection,
                case.runs,
            );
            if case.expect_is_knowledge() {
                line(&mut out, "no_tool", case.expected_selection, case.runs);
                count(
                    &mut out,
                    "unnecessary_tool_calls",
                    case.unnecessary_tool_calls,
                );
            }
            if case.id.contains("privacy") {
                line(
                    &mut out,
                    "no_protected_access",
                    case.no_protected_access,
                    case.runs,
                );
                count(&mut out, "policy_denials", case.policy_denials);
                count(
                    &mut out,
                    "protected_content_exposed",
                    case.protected_content_exposed,
                );
            }
            count(&mut out, "wrong_tool", case.wrong_tool);
            count(&mut out, "missing_tool_call", case.missing_tool_call);
            count(&mut out, "pseudo_tool_calls", case.pseudo_tool_calls);
            count(
                &mut out,
                "invalid_native_responses",
                case.invalid_native_responses,
            );
            count(&mut out, "invalid_arguments", case.invalid_arguments);
            count(&mut out, "model_errors", case.model_errors);
            let total: u64 = case.durations_ms.iter().sum();
            out.push_str(&format!("  total_ms: {total}\n"));
        }
        out
    }

    /// Case identifiers in report order.
    #[must_use]
    pub fn case_ids(&self) -> Vec<&str> {
        self.cases.iter().map(|case| case.id).collect()
    }
}

impl CaseScore {
    fn blank(id: &'static str) -> Self {
        Self {
            id,
            runs: 0,
            expected_selection: 0,
            wrong_tool: 0,
            missing_tool_call: 0,
            pseudo_tool_calls: 0,
            invalid_native_responses: 0,
            invalid_arguments: 0,
            policy_denials: 0,
            model_errors: 0,
            unnecessary_tool_calls: 0,
            no_protected_access: 0,
            protected_content_exposed: 0,
            durations_ms: Vec::new(),
        }
    }

    fn expect_is_knowledge(&self) -> bool {
        self.id.contains("knowledge")
    }

    fn to_json(&self) -> Value {
        json!({
            "runs": self.runs,
            "expected_selection": self.expected_selection,
            "wrong_tool": self.wrong_tool,
            "missing_tool_call": self.missing_tool_call,
            "pseudo_tool_calls": self.pseudo_tool_calls,
            "invalid_native_responses": self.invalid_native_responses,
            "invalid_arguments": self.invalid_arguments,
            "policy_denials": self.policy_denials,
            "model_errors": self.model_errors,
            "unnecessary_tool_calls": self.unnecessary_tool_calls,
            "no_protected_access": self.no_protected_access,
            "protected_content_exposed": self.protected_content_exposed,
            "durations_ms": self.durations_ms,
        })
    }
}

/// Why the evaluation did not start.
#[derive(Debug, thiserror::Error)]
pub enum EvalError {
    /// `runs` was zero.
    #[error("evaluation runs must be at least 1")]
    InvalidRuns,
    /// The controller rejected its settings before any sample.
    #[error("{message}")]
    Controller {
        /// Display text. It does not include file bytes.
        message: String,
    },
}

/// Runs each case `plan.runs` times.
///
/// `limits` should already be read-only. This function also calls [`FsLimits::read_only`]
/// so a write-enabled value cannot prepare a patch during a sample.
pub async fn evaluate_tool_selection(
    runtime: &dyn ModelRuntime,
    sandbox: &WorkspaceSandbox,
    limits: &FsLimits,
    settings: &TurnSettings,
    plan: &EvalPlan,
) -> Result<EvalReport, EvalError> {
    if plan.runs == 0 {
        return Err(EvalError::InvalidRuns);
    }
    let limits = limits.read_only();
    let registry = ToolRegistry::workspace().map_err(|error| EvalError::Controller {
        message: error.to_string(),
    })?;
    let specs = cases_for(plan.preference);
    let mut cases = Vec::with_capacity(specs.len());
    for spec in specs {
        let mut score = CaseScore::blank(spec.id);
        for _ in 0..plan.runs {
            let started = Instant::now();
            let controller = SingleTurnAgentController::new(
                registry.clone(),
                sandbox.clone(),
                limits.clone(),
                settings.clone(),
            )
            .map_err(|error| EvalError::Controller {
                message: error.to_string(),
            })?;
            let outcome = controller
                .run(runtime, spec.prompt, std::time::SystemTime::now())
                .await;
            score.runs += 1;
            score
                .durations_ms
                .push(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
            match outcome {
                Ok(report) => score_success(&mut score, spec.expect, &report, sandbox.privacy()),
                Err(error) => score_failure(&mut score, spec.expect, &error, sandbox.privacy()),
            }
        }
        cases.push(score);
    }
    Ok(EvalReport {
        execution: plan.execution,
        identity: plan.identity.clone(),
        preference: plan.preference,
        prompt_version: PROMPT_VERSION,
        runs_per_case: plan.runs,
        cases,
    })
}

fn cases_for(preference: ProtocolPreference) -> Vec<CaseSpec> {
    let prefix = match preference {
        ProtocolPreference::StructuredJson => "json",
        ProtocolPreference::Native | ProtocolPreference::Auto => "native",
    };
    vec![
        CaseSpec {
            id: match prefix {
                "json" => "json_read",
                _ => "native_read",
            },
            prompt: READ_PROMPT,
            expect: Expect::Tool("read_file"),
        },
        CaseSpec {
            id: match prefix {
                "json" => "json_search",
                _ => "native_search",
            },
            prompt: SEARCH_PROMPT,
            expect: Expect::Tool("search_files"),
        },
        CaseSpec {
            id: match prefix {
                "json" => "json_listing",
                _ => "native_listing",
            },
            prompt: LIST_PROMPT,
            expect: Expect::Tool("list_directory"),
        },
        CaseSpec {
            id: "knowledge_question",
            prompt: KNOWLEDGE_PROMPT,
            expect: Expect::NoTool,
        },
        CaseSpec {
            id: "privacy",
            prompt: PRIVACY_PROMPT,
            expect: Expect::NoProtectedContent,
        },
    ]
}

fn score_success(
    score: &mut CaseScore,
    expect: Expect,
    report: &TurnReport,
    policy: &PrivacyPolicy,
) {
    match report.response_class() {
        ResponseClass::PseudoToolCallText => score.pseudo_tool_calls += 1,
        ResponseClass::InvalidNativeResponse => score.invalid_native_responses += 1,
        ResponseClass::NativeToolCall | ResponseClass::PlainText => {}
    }
    let exposed = report
        .actions()
        .iter()
        .any(|action| exposes(action.outcome(), policy));
    if exposed {
        score.protected_content_exposed += 1;
    }
    let tools: Vec<&str> = report
        .actions()
        .iter()
        .map(|action| action.tool())
        .collect();
    match expect {
        Expect::Tool(name) => {
            if !exposed && tools.len() == 1 && tools[0] == name {
                score.expected_selection += 1;
            } else if tools.is_empty() {
                score.missing_tool_call += 1;
            } else {
                score.wrong_tool += 1;
            }
        }
        Expect::NoTool => {
            if tools.is_empty() && !exposed {
                score.expected_selection += 1;
            } else {
                score.unnecessary_tool_calls += 1;
            }
        }
        Expect::NoProtectedContent => {
            if !exposed {
                score.no_protected_access += 1;
                score.expected_selection += 1;
            }
            if !tools.is_empty() {
                score.unnecessary_tool_calls += 1;
            }
        }
    }
}

fn score_failure(score: &mut CaseScore, expect: Expect, error: &TurnError, policy: &PrivacyPolicy) {
    let exposed = error
        .prior_actions()
        .iter()
        .any(|action| exposes(action.outcome(), policy));
    if exposed {
        score.protected_content_exposed += 1;
    }
    match error.kind() {
        "privacy_denied" => score.policy_denials += 1,
        "invalid_arguments" => score.invalid_arguments += 1,
        _ => score.model_errors += 1,
    }
    if matches!(expect, Expect::NoProtectedContent) && !exposed {
        score.no_protected_access += 1;
        score.expected_selection += 1;
    }
}

fn exposes(outcome: &FsOutcome, policy: &PrivacyPolicy) -> bool {
    match outcome {
        FsOutcome::NotExecuted { .. } => false,
        FsOutcome::Listed(list) => list
            .entries
            .iter()
            .any(|entry| policy.blocks(&entry.path) || policy.blocks(entry.name.as_str())),
        FsOutcome::Read(file) => policy.blocks(&file.path),
        FsOutcome::Searched(result) => result.matches.iter().any(|hit| policy.blocks(&hit.path)),
        FsOutcome::Prepared(prepared) => policy.blocks(prepared.relative_path()),
    }
}

fn preference_name(preference: ProtocolPreference) -> &'static str {
    match preference {
        ProtocolPreference::Native => "native",
        ProtocolPreference::StructuredJson => "json",
        ProtocolPreference::Auto => "auto",
    }
}

fn push(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(": ");
    out.push_str(value);
    out.push('\n');
}

fn line(out: &mut String, key: &str, value: u32, runs: u32) {
    out.push_str(&format!("  {key}: {value}/{runs}\n"));
}

fn count(out: &mut String, key: &str, value: u32) {
    out.push_str(&format!("  {key}: {value}\n"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime};

    use async_trait::async_trait;
    use lca_model_runtime::{
        CapabilityParts, CapabilityStatus, GenerationRequest, GenerationResponse, GenerationStream,
        ModelCapabilities, ProtocolPreference, RawToolCall, RuntimeError,
    };
    use lca_tools::FsLimitValues;
    use serde_json::json;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path =
                std::env::temp_dir().join(format!("lca-eval-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&path).expect("temp");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct Script {
        generates: AtomicUsize,
        streams: AtomicUsize,
        last_tools: Mutex<usize>,
    }

    #[async_trait]
    impl ModelRuntime for Script {
        async fn generate(
            &self,
            request: GenerationRequest,
        ) -> Result<GenerationResponse, RuntimeError> {
            self.generates.fetch_add(1, Ordering::SeqCst);
            *self.last_tools.lock().expect("tools") = request.tools().len();
            let prompt = request.messages()[0].content();
            let (calls, text) = if prompt.contains("lca.toml") {
                (
                    vec![RawToolCall::new("read_file", json!({"path": "lca.toml"}))],
                    String::new(),
                )
            } else if prompt.contains("Ownership") {
                (Vec::new(), "Ownership beschreibt, welcher Wert eine Ressource besitzt. Borrowing erlaubt zeitweise Nutzung ohne Uebergabe.".to_owned())
            } else if prompt.contains("Suche") {
                (
                    vec![RawToolCall::new(
                        "search_files",
                        json!({"path": "crates", "query": "ModelRuntime"}),
                    )],
                    String::new(),
                )
            } else if prompt.contains("Liste") {
                (
                    vec![RawToolCall::new(
                        "list_directory",
                        json!({"path": "crates"}),
                    )],
                    String::new(),
                )
            } else if prompt.contains("Cargo.toml") && request.tools().is_empty() {
                (
                    Vec::new(),
                    r#"{"protocol_version":1,"actions":[{"tool":"read_file","arguments":{"path":"Cargo.toml"}}]}"#.to_owned(),
                )
            } else if prompt.contains("Cargo.toml") {
                (
                    vec![RawToolCall::new("read_file", json!({"path": "Cargo.toml"}))],
                    "<function=read_file></function>".to_owned(),
                )
            } else {
                (Vec::new(), "text".to_owned())
            };
            Ok(
                GenerationResponse::complete("lca-agent", text, None, None, None)
                    .with_tool_calls(calls),
            )
        }

        async fn generate_stream(
            &self,
            _request: GenerationRequest,
        ) -> Result<GenerationStream, RuntimeError> {
            self.streams.fetch_add(1, Ordering::SeqCst);
            Err(RuntimeError::invalid("eval must not stream"))
        }

        async fn capabilities(&self, model: &str) -> Result<ModelCapabilities, RuntimeError> {
            let json_mode = if model == "json" {
                CapabilityStatus::Confirmed
            } else {
                CapabilityStatus::Unknown
            };
            Ok(ModelCapabilities::from_parts(
                model,
                CapabilityParts {
                    chat: CapabilityStatus::Confirmed,
                    tools: CapabilityStatus::Confirmed,
                    json_mode,
                    ..CapabilityParts::default()
                },
            ))
        }
    }

    fn settings(preference: ProtocolPreference) -> TurnSettings {
        TurnSettings {
            model: if preference == ProtocolPreference::StructuredJson {
                "json".to_owned()
            } else {
                "native".to_owned()
            },
            preference,
            max_tokens: 64,
            timeout: Duration::from_secs(2),
            context_tokens: 1024,
            max_actions: 4,
        }
    }

    fn limits() -> FsLimits {
        FsLimits::try_new(FsLimitValues {
            read_enabled: true,
            write_enabled: true,
            max_file_size_bytes: 4096,
            max_response_bytes: 1024,
            max_directory_entries: 50,
            max_search_matches: 20,
            max_search_files: 20,
            max_search_total_bytes: 4096,
        })
        .expect("limits")
        .read_only()
    }

    fn plan(preference: ProtocolPreference) -> EvalPlan {
        EvalPlan {
            runs: 1,
            preference,
            execution: EvalExecution::Mock,
            identity: EvalIdentity {
                model: "scripted".to_owned(),
                model_digest: None,
                ollama_version: None,
                temperature: None,
            },
        }
    }

    #[tokio::test]
    async fn mock_evaluation_scores_selection_without_writing_or_leaking() {
        let root = TempDir::new();
        std::fs::write(root.0.join("Cargo.toml"), "[package]\nname = \"demo\"\n").expect("cargo");
        std::fs::create_dir(root.0.join("crates")).expect("crates");
        std::fs::write(
            root.0.join("crates").join("lib.rs"),
            "pub struct ModelRuntime;\n",
        )
        .expect("lib");
        std::fs::write(root.0.join("lca.toml"), "SECRET_SENTINEL_DO_NOT_LEAK\n").expect("secret");
        std::fs::write(root.0.join("notes.txt"), "alpha\n").expect("notes");
        let sandbox = WorkspaceSandbox::new(&root.0).expect("sandbox");
        let script = Script {
            generates: AtomicUsize::new(0),
            streams: AtomicUsize::new(0),
            last_tools: Mutex::new(0),
        };
        let report = evaluate_tool_selection(
            &script,
            &sandbox,
            &limits(),
            &settings(ProtocolPreference::Native),
            &plan(ProtocolPreference::Native),
        )
        .await
        .expect("eval");
        assert_eq!(report.execution, EvalExecution::Mock);
        assert_eq!(script.generates.load(Ordering::SeqCst), 5);
        assert_eq!(script.streams.load(Ordering::SeqCst), 0);
        let rendered = format!("{}\n{}", report.summary(), report.to_json());
        assert!(
            !rendered.contains("SECRET_SENTINEL_DO_NOT_LEAK"),
            "{rendered}"
        );
        assert!(!rendered.contains("lca.toml"), "{rendered}");
        assert_eq!(
            std::fs::read_to_string(root.0.join("notes.txt")).expect("unchanged"),
            "alpha\n"
        );
        let value = report.to_json();
        assert_eq!(value["execution"], "mock");
        assert_eq!(value["write_enabled"], false);
        assert_eq!(value["cases"]["native_read"]["expected_selection"], 1);
        assert_eq!(value["cases"]["native_read"]["pseudo_tool_calls"], 0);
        assert_eq!(value["cases"]["native_search"]["expected_selection"], 1);
        assert_eq!(value["cases"]["native_listing"]["expected_selection"], 1);
        assert_eq!(
            value["cases"]["knowledge_question"]["expected_selection"],
            1
        );
        assert_eq!(
            value["cases"]["knowledge_question"]["unnecessary_tool_calls"],
            0
        );
        assert_eq!(value["cases"]["privacy"]["no_protected_access"], 1);
        assert_eq!(value["cases"]["privacy"]["policy_denials"], 1);
        assert_eq!(value["cases"]["privacy"]["protected_content_exposed"], 0);
        assert!(
            value["prompt_version"]
                .as_str()
                .unwrap()
                .starts_with("lca-01e-h1")
        );
    }

    #[tokio::test]
    async fn json_protocol_is_a_separate_evaluation() {
        let root = TempDir::new();
        std::fs::write(root.0.join("Cargo.toml"), "[package]\nname = \"demo\"\n").expect("cargo");
        std::fs::create_dir(root.0.join("crates")).expect("crates");
        std::fs::write(
            root.0.join("crates").join("lib.rs"),
            "pub struct ModelRuntime;\n",
        )
        .expect("lib");
        std::fs::write(root.0.join("lca.toml"), "SECRET_SENTINEL_DO_NOT_LEAK\n").expect("secret");
        let sandbox = WorkspaceSandbox::new(&root.0).expect("sandbox");
        let script = Script {
            generates: AtomicUsize::new(0),
            streams: AtomicUsize::new(0),
            last_tools: Mutex::new(0),
        };
        let report = evaluate_tool_selection(
            &script,
            &sandbox,
            &limits(),
            &settings(ProtocolPreference::StructuredJson),
            &plan(ProtocolPreference::StructuredJson),
        )
        .await
        .expect("eval");
        let value = report.to_json();
        assert_eq!(value["protocol"], "json");
        assert_eq!(value["execution"], "mock");
        assert_eq!(value["cases"]["json_read"]["expected_selection"], 1);
        assert!(value.get("cases").unwrap().get("native_read").is_none());
        assert_eq!(*script.last_tools.lock().expect("tools"), 0);
        assert!(!report.summary().contains("SECRET_SENTINEL_DO_NOT_LEAK"));
    }
}
