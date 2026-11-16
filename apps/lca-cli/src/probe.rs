//! `lca tools probe` asks a local model for `diagnostic_echo` and validates the proposal.
//!
//! The command does not execute the tool. Native tool calls and the JSON action document
//! share one validator. A response with no action is a failed probe, not a success.
//! The selected protocol is not changed after the model responds.

use std::path::PathBuf;
use std::time::Duration;

use lca_config::load_from_path;
use lca_model_runtime::{
    GenerationOptions, GenerationRequest, GenerationResponse, Message, ModelRuntime,
    ProtocolAvailability, ProtocolPreference, ProtocolSelectionError, RawToolCall, ResponseFormat,
    RuntimeError, SelectedProtocol, ToolDefinition, report,
};
use lca_ollama::{OllamaModelRuntime, OllamaRuntimeConfig};
use lca_tools::{
    ActionIdFactory, ActionSource, ActionValidationError, JsonProtocolError, RegistryError,
    ToolCallBatch, ToolRegistry, parse_action_document, propose_actions, validate_batch,
};
use serde_json::Value;

use crate::CommandOutput;

/// The JSON document is an implemented, strictly validated protocol.
///
/// Ollama's `format: json` is requested only when the backend confirms JSON mode.
/// Confirmation is not required to select the fallback, and it is not a promise that
/// the model will emit the document.
const JSON_FALLBACK_ALLOWED: bool = true;

const NATIVE_PROMPT: &str = "\
Call the diagnostic_echo tool exactly once. \
Set the message argument to hello. \
Do not answer with prose, markdown, or a textual tool-call marker.";

const JSON_PROMPT: &str = "\
Return only a JSON object and no other text. \
Use protocol_version 1. \
Include one action whose tool is diagnostic_echo and whose arguments message is hello. \
Do not use markdown.";

/// Arguments for `lca tools probe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCommand {
    /// Configuration file selected by `--config`, or `lca.toml`.
    pub config: PathBuf,
    /// Requested protocol.
    pub protocol: ProtocolPreference,
}

/// Loads configuration, probes the runtime, and renders a buffered result.
pub fn run_probe(command: &ProbeCommand) -> CommandOutput {
    let config = match load_from_path(&command.config) {
        Ok(config) => config,
        Err(error) => return failure(&error.to_string()),
    };
    let runtime = match OllamaModelRuntime::connect(OllamaRuntimeConfig::new(
        config.endpoint(),
        config.connect_timeout(),
        config.request_timeout(),
    )) {
        Ok(runtime) => runtime,
        Err(error) => return failure(&report(&error)),
    };
    let tokio_runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return failure(&format!("failed to start the runtime: {error}")),
    };
    let input = ProbeInput {
        model: config.model().to_owned(),
        preference: command.protocol,
        max_tokens: config.generation_limit(),
        timeout: config.request_timeout(),
        context_tokens: config.context_window(),
    };
    match tokio_runtime.block_on(probe_model(&runtime, &input)) {
        Ok(report) => CommandOutput {
            exit_code: 0,
            stdout: render_report(&report),
            stderr: String::new(),
        },
        Err(error) => failure(&error.to_string()),
    }
}

struct ProbeInput {
    model: String,
    preference: ProtocolPreference,
    max_tokens: u32,
    timeout: Duration,
    context_tokens: u32,
}

#[derive(Debug)]
struct ProbeReport {
    protocol: SelectedProtocol,
    batch: ToolCallBatch,
}

#[derive(Debug)]
enum ProbeFailure {
    Runtime(RuntimeError),
    Protocol(ProtocolSelectionError),
    Json(JsonProtocolError),
    Validation(ActionValidationError),
    Registry(RegistryError),
    NoAction,
}

impl std::fmt::Display for ProbeFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(error) => formatter.write_str(&report(error)),
            Self::Protocol(error) => write!(formatter, "{error}"),
            Self::Json(error) => write!(formatter, "{error}"),
            Self::Validation(error) => write!(formatter, "{error}"),
            Self::Registry(error) => write!(formatter, "{error}"),
            Self::NoAction => formatter.write_str("model produced no tool call"),
        }
    }
}

async fn probe_model(
    runtime: &dyn ModelRuntime,
    input: &ProbeInput,
) -> Result<ProbeReport, ProbeFailure> {
    let registry = ToolRegistry::diagnostic().map_err(ProbeFailure::Registry)?;
    let capabilities = runtime
        .capabilities(&input.model)
        .await
        .map_err(ProbeFailure::Runtime)?;
    let protocol = select_once(input.preference, &capabilities)?;
    let request = generation_request(&registry, input, protocol)?;
    let response = runtime
        .generate(request)
        .await
        .map_err(ProbeFailure::Runtime)?;
    let pairs = proposed_calls(protocol, &response)?;
    let actions = propose_actions(&ActionIdFactory::new(), source_of(protocol), pairs);
    let batch = validate_batch(&registry, &actions).map_err(ProbeFailure::Validation)?;
    if batch.is_empty() {
        return Err(ProbeFailure::NoAction);
    }
    Ok(ProbeReport { protocol, batch })
}

fn select_once(
    preference: ProtocolPreference,
    capabilities: &lca_model_runtime::ModelCapabilities,
) -> Result<SelectedProtocol, ProbeFailure> {
    lca_model_runtime::select_protocol(
        preference,
        capabilities,
        ProtocolAvailability::new(JSON_FALLBACK_ALLOWED),
    )
    .map_err(ProbeFailure::Protocol)
}

fn generation_request(
    registry: &ToolRegistry,
    input: &ProbeInput,
    protocol: SelectedProtocol,
) -> Result<GenerationRequest, ProbeFailure> {
    let (prompt, tools, response_format) = match protocol {
        SelectedProtocol::Native => (
            NATIVE_PROMPT,
            diagnostic_definitions(registry)?,
            ResponseFormat::Text,
        ),
        SelectedProtocol::StructuredJson {
            json_mode_confirmed: true,
        } => (JSON_PROMPT, Vec::new(), ResponseFormat::Json),
        SelectedProtocol::StructuredJson {
            json_mode_confirmed: false,
        } => (JSON_PROMPT, Vec::new(), ResponseFormat::Text),
    };
    GenerationRequest::try_new(
        &input.model,
        vec![Message::user(prompt)],
        GenerationOptions {
            tools,
            response_format,
            max_tokens: Some(input.max_tokens),
            timeout: Some(input.timeout),
            context_tokens: Some(input.context_tokens),
            ..GenerationOptions::default()
        },
    )
    .map_err(ProbeFailure::Runtime)
}

fn diagnostic_definitions(registry: &ToolRegistry) -> Result<Vec<ToolDefinition>, ProbeFailure> {
    registry
        .iter()
        .map(|tool| {
            ToolDefinition::try_new(tool.name(), tool.description(), tool.schema().clone())
                .map_err(ProbeFailure::Runtime)
        })
        .collect()
}

fn proposed_calls(
    protocol: SelectedProtocol,
    response: &GenerationResponse,
) -> Result<Vec<(String, Value)>, ProbeFailure> {
    match protocol {
        SelectedProtocol::Native => Ok(response.tool_calls().iter().map(raw_call).collect()),
        SelectedProtocol::StructuredJson { .. } => parse_action_document(response.text())
            .map_err(ProbeFailure::Json)
            .map(|actions| {
                actions
                    .into_iter()
                    .map(|action| (action.tool().to_owned(), action.arguments().clone()))
                    .collect()
            }),
    }
}

fn raw_call(call: &RawToolCall) -> (String, Value) {
    (call.name().to_owned(), call.arguments().clone())
}

fn source_of(protocol: SelectedProtocol) -> ActionSource {
    match protocol {
        SelectedProtocol::Native => ActionSource::Native,
        SelectedProtocol::StructuredJson { .. } => ActionSource::StructuredJson,
    }
}

fn render_report(report: &ProbeReport) -> String {
    let mut out = String::new();
    push(&mut out, "protocol", report.protocol.as_str());
    for action in report.batch.actions() {
        push(&mut out, "tool", action.name());
        push(&mut out, "validation", "passed");
        push(&mut out, "execution", "disabled");
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use lca_model_runtime::{
        CapabilityParts, CapabilityStatus, GenerationStream, ModelCapabilities,
    };
    use serde_json::json;

    struct MockRuntime {
        tools: CapabilityStatus,
        json_mode: CapabilityStatus,
        response: GenerationResponse,
        calls: AtomicUsize,
        last: Mutex<Option<GenerationRequest>>,
    }

    #[async_trait]
    impl ModelRuntime for MockRuntime {
        async fn generate(
            &self,
            request: GenerationRequest,
        ) -> Result<GenerationResponse, RuntimeError> {
            request.validate()?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.last.lock().expect("request lock") = Some(request);
            Ok(self.response.clone())
        }

        async fn generate_stream(
            &self,
            _request: GenerationRequest,
        ) -> Result<GenerationStream, RuntimeError> {
            Err(RuntimeError::invalid("probe must not stream"))
        }

        async fn capabilities(&self, model: &str) -> Result<ModelCapabilities, RuntimeError> {
            Ok(ModelCapabilities::from_parts(
                model,
                CapabilityParts {
                    chat: CapabilityStatus::Confirmed,
                    tools: self.tools,
                    json_mode: self.json_mode,
                    ..CapabilityParts::default()
                },
            ))
        }
    }

    fn input(preference: ProtocolPreference) -> ProbeInput {
        ProbeInput {
            model: "lca-agent".to_owned(),
            preference,
            max_tokens: 64,
            timeout: Duration::from_secs(5),
            context_tokens: 1024,
        }
    }

    fn native_response(calls: Vec<RawToolCall>, text: &str) -> GenerationResponse {
        GenerationResponse::complete("lca-agent", text, None, None, None).with_tool_calls(calls)
    }

    fn echo_call(message: &str) -> RawToolCall {
        RawToolCall::new("diagnostic_echo", json!({"message": message}))
    }

    #[tokio::test]
    async fn native_probe_validates_one_call_and_does_not_execute_it() {
        let runtime = MockRuntime {
            tools: CapabilityStatus::Confirmed,
            json_mode: CapabilityStatus::Unknown,
            response: native_response(vec![echo_call("hello")], "<tool_call>ignored</tool_call>"),
            calls: AtomicUsize::new(0),
            last: Mutex::new(None),
        };
        let root = std::env::temp_dir().join(format!("lca-probe-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("temp");
        let secret = root.join("secret.txt");
        std::fs::write(&secret, "SENTINEL_DO_NOT_LEAK").expect("secret");

        let report = probe_model(&runtime, &input(ProtocolPreference::Native))
            .await
            .expect("probe");
        let stdout = render_report(&report);
        assert_eq!(
            stdout,
            "protocol: native\ntool: diagnostic_echo\nvalidation: passed\nexecution: disabled\n"
        );
        assert_eq!(runtime.calls.load(Ordering::SeqCst), 1);
        let request = runtime.last.lock().expect("lock").clone().expect("request");
        assert_eq!(request.tools().len(), 1);
        assert_eq!(request.tools()[0].name(), "diagnostic_echo");
        assert_eq!(request.response_format(), ResponseFormat::Text);
        assert!(request.messages()[0].content().contains("diagnostic_echo"));
        assert_eq!(
            std::fs::read_to_string(&secret).expect("unchanged"),
            "SENTINEL_DO_NOT_LEAK"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn text_markers_and_json_bodies_do_not_switch_a_native_probe() {
        let json_body = r#"{"protocol_version":1,"actions":[{"tool":"diagnostic_echo","arguments":{"message":"from-json"}}]}"#;
        let runtime = MockRuntime {
            tools: CapabilityStatus::Confirmed,
            json_mode: CapabilityStatus::Confirmed,
            response: native_response(Vec::new(), json_body),
            calls: AtomicUsize::new(0),
            last: Mutex::new(None),
        };
        let error = probe_model(&runtime, &input(ProtocolPreference::Auto))
            .await
            .expect_err("empty");
        assert!(error.to_string().contains("no tool call"), "{error}");
        assert_eq!(runtime.calls.load(Ordering::SeqCst), 1);

        let runtime = MockRuntime {
            tools: CapabilityStatus::Confirmed,
            json_mode: CapabilityStatus::Confirmed,
            response: native_response(vec![echo_call("from-native")], json_body),
            calls: AtomicUsize::new(0),
            last: Mutex::new(None),
        };
        let report = probe_model(&runtime, &input(ProtocolPreference::Native))
            .await
            .expect("native");
        assert_eq!(report.batch.len(), 1);
        assert_eq!(
            report.batch.actions()[0].arguments().as_value()["message"],
            "from-native"
        );
        assert_eq!(report.batch.actions()[0].source(), ActionSource::Native);
    }

    #[tokio::test]
    async fn json_probe_validates_the_document_and_records_json_mode() {
        let body = r#"{"protocol_version":1,"actions":[{"tool":"diagnostic_echo","arguments":{"message":"hello"}},{"tool":"diagnostic_echo","arguments":{"message":"again"}}]}"#;
        let runtime = MockRuntime {
            tools: CapabilityStatus::NotReported,
            json_mode: CapabilityStatus::Unknown,
            response: native_response(vec![echo_call("from-native")], body),
            calls: AtomicUsize::new(0),
            last: Mutex::new(None),
        };
        let report = probe_model(&runtime, &input(ProtocolPreference::StructuredJson))
            .await
            .expect("json");
        let stdout = render_report(&report);
        assert_eq!(stdout.matches("tool: diagnostic_echo").count(), 2);
        assert_eq!(stdout.matches("execution: disabled").count(), 2);
        assert!(stdout.starts_with("protocol: json\n"), "{stdout}");
        assert_eq!(
            report.batch.actions()[0].source(),
            ActionSource::StructuredJson
        );
        assert_eq!(
            report.batch.actions()[0].arguments().as_value()["message"],
            "hello"
        );
        let request = runtime.last.lock().expect("lock").clone().expect("request");
        assert!(request.tools().is_empty());
        assert_eq!(request.response_format(), ResponseFormat::Text);

        let runtime = MockRuntime {
            tools: CapabilityStatus::Unknown,
            json_mode: CapabilityStatus::Confirmed,
            response: GenerationResponse::complete("lca-agent", body, None, None, None),
            calls: AtomicUsize::new(0),
            last: Mutex::new(None),
        };
        let report = probe_model(&runtime, &input(ProtocolPreference::Auto))
            .await
            .expect("auto json");
        assert_eq!(report.protocol.as_str(), "json");
        assert!(report.protocol.json_mode_confirmed());
        let request = runtime.last.lock().expect("lock").clone().expect("request");
        assert_eq!(request.response_format(), ResponseFormat::Json);
        assert!(request.tools().is_empty());
    }

    #[tokio::test]
    async fn unconfirmed_native_and_invalid_payloads_fail_closed() {
        let runtime = MockRuntime {
            tools: CapabilityStatus::Unknown,
            json_mode: CapabilityStatus::Confirmed,
            response: native_response(vec![echo_call("hello")], ""),
            calls: AtomicUsize::new(0),
            last: Mutex::new(None),
        };
        let error = probe_model(&runtime, &input(ProtocolPreference::Native))
            .await
            .expect_err("native");
        assert!(error.to_string().contains("not confirmed"), "{error}");
        assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);

        let runtime = MockRuntime {
            tools: CapabilityStatus::NotReported,
            json_mode: CapabilityStatus::Unknown,
            response: GenerationResponse::complete(
                "lca-agent",
                "```json\n{\"protocol_version\":1,\"actions\":[]}\n```",
                None,
                None,
                None,
            ),
            calls: AtomicUsize::new(0),
            last: Mutex::new(None),
        };
        let error = probe_model(&runtime, &input(ProtocolPreference::StructuredJson))
            .await
            .expect_err("markdown");
        assert!(error.to_string().contains("markdown"), "{error}");

        let runtime = MockRuntime {
            tools: CapabilityStatus::Confirmed,
            json_mode: CapabilityStatus::Unknown,
            response: native_response(
                vec![RawToolCall::new(
                    "execute_command",
                    json!({"command": "do-not-run"}),
                )],
                "",
            ),
            calls: AtomicUsize::new(0),
            last: Mutex::new(None),
        };
        let error = probe_model(&runtime, &input(ProtocolPreference::Native))
            .await
            .expect_err("unknown");
        assert!(error.to_string().contains("unknown tool"), "{error}");
        assert!(!error.to_string().contains("do-not-run"), "{error}");
    }
}
