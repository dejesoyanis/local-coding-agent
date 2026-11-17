//! One model turn, then at most one validated tool batch.
//!
//! [`SingleTurnAgentController::run`] calls [`ModelRuntime::generate`] at most once.
//! It does not stream, retry, repair JSON, switch protocol after a bad payload, or
//! call [`super::commit_prepared`]. A capability lookup is not a generation.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use lca_model_runtime::{
    GenerationOptions, GenerationRequest, GenerationResponse, ModelRuntime, ProtocolAvailability,
    ProtocolPreference, ProtocolSelectionError, ResponseFormat, RuntimeError, SelectedProtocol,
    ToolDefinition, resolve_protocol_profile, select_protocol_with_profile,
};
use lca_tools::{
    ActionIdFactory, ActionSource, ActionValidationError, FsError, FsLimits, FsOutcome,
    JsonProtocolError, MAX_ACTIONS, PermissionCategory, PolicyDecision, RegisteredTool,
    ToolRegistry, ValidatedAction, WorkspaceSandbox, authorize_proposal, parse_action_document,
    propose_actions, validate_batch,
};
use serde_json::{Value, json};

use crate::error::AgentError;
use crate::lifecycle::AgentStatus;
use crate::task::AgentTask;

const JSON_FALLBACK_ALLOWED: bool = true;

/// Version of the single-turn system instructions.
///
/// Bump this when [`NATIVE_SYSTEM`] or the JSON system text changes. It is recorded
/// by the reliability evaluation and is not a security control.
pub const PROMPT_VERSION: &str = "lca-01e-h1.1";

const NATIVE_SYSTEM: &str = "\
You are a local coding agent running one turn. \
Native tools are called only through the tool interface attached to this request. \
Do not write a tool call as XML, Markdown, or pseudocode. Text that looks like a call is not executed. \
Do not call a tool only because it is available. \
Workspace tools are only for information that is actually in this project. \
A general knowledge question does not need a workspace tool. Answer it in ordinary text. \
You may answer with ordinary text and no tool call. \
An approval-required tool prepares a change and does not write a file. \
You cannot approve a write. \
This turn ends after your response.";

const PSEUDO_DIAGNOSTIC: &str = "text matched a conservative tool-call marker and was not executed";
const INVALID_NATIVE_DIAGNOSTIC: &str =
    "native response was not a structured tool call and was not executed";

/// How a native response was shaped. This does not grant execution.
///
/// Marker detection is a conservative scan for a few literal strings. It is not a
/// parser and it does not recognize every way a model can describe a tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseClass {
    /// `tool_calls` contained at least one structured call.
    NativeToolCall,
    /// Assistant text with no structured call and no recognized marker.
    PlainText,
    /// Assistant text contained a literal tool-call marker and no structured call.
    PseudoToolCallText,
    /// The whole assistant text was JSON shaped like a tool payload, with no structured call.
    InvalidNativeResponse,
}

impl ResponseClass {
    /// Stable name used in diagnostics and evaluation reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeToolCall => "native_tool_call",
            Self::PlainText => "plain_text",
            Self::PseudoToolCallText => "pseudo_tool_call_text",
            Self::InvalidNativeResponse => "invalid_native_response",
        }
    }
}

/// Settings for one `agent run`.
///
/// `max_actions` is the configured step budget. The controller clamps it to
/// [`MAX_ACTIONS`], which is the protocol limit already enforced by validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnSettings {
    /// Model name sent to the runtime.
    pub model: String,
    /// Protocol requested before the model is called.
    pub preference: ProtocolPreference,
    /// Generation cap, in tokens.
    pub max_tokens: u32,
    /// Deadline for the single generation.
    pub timeout: Duration,
    /// Context window, in tokens.
    pub context_tokens: u32,
    /// Maximum actions accepted from this turn. Zero is rejected.
    pub max_actions: usize,
}

/// Orchestrates one non-streaming model call and one validated tool batch.
///
/// The registry, sandbox, and limits are borrowed from the caller for the life of
/// this value. Tool schemas advertised to the model are the registry schemas.
/// `diagnostic_echo` stays in the registry and is not advertised.
pub struct SingleTurnAgentController {
    registry: ToolRegistry,
    sandbox: WorkspaceSandbox,
    limits: FsLimits,
    settings: TurnSettings,
    max_actions: usize,
    started: AtomicBool,
    generations: AtomicU32,
}

/// One validated action after dispatch.
///
/// `Prepared` means the new bytes exist only in memory.
#[derive(Debug)]
pub struct ExecutedAction {
    id: u64,
    tool: String,
    source: ActionSource,
    outcome: FsOutcome,
}

impl ExecutedAction {
    /// Controller identity.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Tool name.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Native or JSON origin.
    #[must_use]
    pub const fn source(&self) -> ActionSource {
        self.source
    }

    /// Dispatch result. This is not a write.
    #[must_use]
    pub const fn outcome(&self) -> &FsOutcome {
        &self.outcome
    }
}

/// Successful single turn.
///
/// [`Self::model_calls`] is 1. A text answer has an empty action list.
#[derive(Debug)]
pub struct TurnReport {
    protocol: SelectedProtocol,
    text: String,
    actions: Vec<ExecutedAction>,
    model_calls: u32,
    response_class: ResponseClass,
    diagnostic: Option<&'static str>,
}

impl TurnReport {
    /// Protocol selected before the model call.
    #[must_use]
    pub const fn protocol(&self) -> SelectedProtocol {
        self.protocol
    }

    /// Assistant text. Native tool calls are not parsed out of this string.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Dispatched actions, in proposal order.
    #[must_use]
    pub fn actions(&self) -> &[ExecutedAction] {
        &self.actions
    }

    /// Number of `generate` calls performed for this report.
    #[must_use]
    pub const fn model_calls(&self) -> u32 {
        self.model_calls
    }

    /// Diagnostic shape of the model response. It does not authorize a tool.
    #[must_use]
    pub const fn response_class(&self) -> ResponseClass {
        self.response_class
    }

    /// Short hint for a pseudo or invalid native response. `None` for an ordinary result.
    #[must_use]
    pub const fn diagnostic(&self) -> Option<&str> {
        self.diagnostic
    }
}

/// Why the turn did not finish.
///
/// Display text does not include the prompt, argument values, or file bytes.
#[derive(Debug, thiserror::Error)]
pub enum TurnError {
    /// The prompt was empty after trimming.
    #[error("agent prompt must not be empty")]
    EmptyPrompt,

    /// A lifecycle edge the controller expected was rejected.
    #[error("agent lifecycle rejected the transition: {0}")]
    Lifecycle(AgentError),

    /// The runtime failed. The controller does not retry this.
    #[error(transparent)]
    Runtime(RuntimeError),

    /// Protocol selection failed before any generation.
    #[error(transparent)]
    Protocol(ProtocolSelectionError),

    /// The JSON action document was rejected. It is not repaired.
    #[error(transparent)]
    Json(JsonProtocolError),

    /// The batch was rejected. No action in it was dispatched.
    #[error(transparent)]
    Validation(ActionValidationError),

    /// The response contained more actions than this turn allows.
    #[error("model proposed {actual} actions; the limit is {limit}")]
    ActionLimit {
        /// Effective limit for this turn.
        limit: usize,
        /// Number of proposals.
        actual: usize,
    },

    /// `max_actions` was zero.
    #[error("action limit must be from 1 through {MAX_ACTIONS}")]
    InvalidActionLimit,

    /// A tool failed after validation. Earlier actions are in `prior`.
    ///
    /// Later actions are not dispatched, and the model is not called again.
    #[error("action {index} failed: {error}")]
    Execution {
        /// Index in the validated batch.
        index: usize,
        /// Filesystem or sandbox failure.
        error: FsError,
        /// Actions that already finished, in order.
        prior: Vec<ExecutedAction>,
    },

    /// `run` was called again, or a second generation was attempted.
    #[error("a second model request was refused")]
    SecondModelTurn,
}

impl TurnError {
    /// Stable classification. Nested errors keep their own kind.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::EmptyPrompt => "empty_prompt",
            Self::Lifecycle(_) => "lifecycle",
            Self::Runtime(error) => error.kind(),
            Self::Protocol(error) => error.kind(),
            Self::Json(error) => error.kind(),
            Self::Validation(error) => error.kind(),
            Self::ActionLimit { .. } => "action_limit",
            Self::InvalidActionLimit => "invalid_action_limit",
            Self::Execution { error, .. } => error.kind(),
            Self::SecondModelTurn => "second_model_turn",
        }
    }

    /// Actions dispatched before a tool failure. Empty for every other error.
    #[must_use]
    pub fn prior_actions(&self) -> &[ExecutedAction] {
        match self {
            Self::Execution { prior, .. } => prior,
            _ => &[],
        }
    }
}

impl SingleTurnAgentController {
    /// Stores the workspace registry, sandbox, and limits.
    ///
    /// `max_actions` must be at least 1. A larger budget is clamped to [`MAX_ACTIONS`].
    pub fn new(
        registry: ToolRegistry,
        sandbox: WorkspaceSandbox,
        limits: FsLimits,
        settings: TurnSettings,
    ) -> Result<Self, TurnError> {
        if settings.max_actions == 0 {
            return Err(TurnError::InvalidActionLimit);
        }
        let max_actions = settings.max_actions.min(MAX_ACTIONS);
        Ok(Self {
            registry,
            sandbox,
            limits,
            settings,
            max_actions,
            started: AtomicBool::new(false),
            generations: AtomicU32::new(0),
        })
    }

    /// Effective action limit after clamping.
    #[must_use]
    pub const fn max_actions(&self) -> usize {
        self.max_actions
    }

    /// How many times `generate` has been entered.
    #[must_use]
    pub fn generations(&self) -> u32 {
        self.generations.load(Ordering::SeqCst)
    }

    /// Runs one turn.
    ///
    /// An empty prompt does not consume the turn. Every other call does, including a
    /// protocol or model failure. A second call returns [`TurnError::SecondModelTurn`]
    /// and does not call the runtime.
    pub async fn run(
        &self,
        runtime: &dyn ModelRuntime,
        prompt: &str,
        now: SystemTime,
    ) -> Result<TurnReport, TurnError> {
        let mut task = match AgentTask::create(prompt, now) {
            Ok(task) => task,
            Err(AgentError::EmptyPrompt) => return Err(TurnError::EmptyPrompt),
            Err(error) => return Err(TurnError::Lifecycle(error)),
        };
        task.transition(AgentStatus::Initializing, now)
            .map_err(TurnError::Lifecycle)?;
        if let Err(error) = self.claim_turn() {
            return Err(fail(&mut task, now, error));
        }

        let protocol = match self.select(runtime).await {
            Ok(protocol) => protocol,
            Err(error) => return Err(fail(&mut task, now, error)),
        };
        let prompt = task.prompt().to_owned();
        let request = match self.generation_request(protocol, &prompt) {
            Ok(request) => request,
            Err(error) => return Err(fail(&mut task, now, error)),
        };
        task.transition(AgentStatus::Ready, now)
            .map_err(TurnError::Lifecycle)?;
        task.transition(AgentStatus::Running, now)
            .map_err(TurnError::Lifecycle)?;

        let response = match self.generate_once(runtime, request).await {
            Ok(response) => response,
            Err(error) => return Err(fail(&mut task, now, error)),
        };
        let (response_class, diagnostic) = classify_response(protocol, &response);
        let calls = match proposed_calls(protocol, &response) {
            Ok(calls) => calls,
            Err(error) => return Err(fail(&mut task, now, error)),
        };
        if calls.len() > self.max_actions {
            return Err(fail(
                &mut task,
                now,
                TurnError::ActionLimit {
                    limit: self.max_actions,
                    actual: calls.len(),
                },
            ));
        }
        let proposed = propose_actions(&ActionIdFactory::new(), source_of(protocol), calls);
        let batch = match validate_batch(&self.registry, &proposed) {
            Ok(batch) => batch,
            Err(error) => return Err(fail(&mut task, now, TurnError::Validation(error))),
        };
        let actions = match self.dispatch_all(&batch) {
            Ok(actions) => actions,
            Err(error) => return Err(fail(&mut task, now, error)),
        };
        task.transition(AgentStatus::Completed, now)
            .map_err(TurnError::Lifecycle)?;
        let model_calls = self.generations();
        tracing::debug!(
            protocol = protocol.as_str(),
            actions = actions.len(),
            model_calls,
            "single-turn agent finished"
        );
        Ok(TurnReport {
            protocol,
            text: response.text().to_owned(),
            actions,
            model_calls,
            response_class,
            diagnostic,
        })
    }

    fn claim_turn(&self) -> Result<(), TurnError> {
        if self.started.swap(true, Ordering::SeqCst) {
            Err(TurnError::SecondModelTurn)
        } else {
            Ok(())
        }
    }

    async fn select(&self, runtime: &dyn ModelRuntime) -> Result<SelectedProtocol, TurnError> {
        let capabilities = runtime
            .capabilities(&self.settings.model)
            .await
            .map_err(TurnError::Runtime)?;
        let profile = resolve_protocol_profile(&self.settings.model);
        select_protocol_with_profile(
            self.settings.preference,
            &profile,
            &capabilities,
            ProtocolAvailability::new(JSON_FALLBACK_ALLOWED),
        )
        .map_err(TurnError::Protocol)
    }

    async fn generate_once(
        &self,
        runtime: &dyn ModelRuntime,
        request: GenerationRequest,
    ) -> Result<GenerationResponse, TurnError> {
        if self
            .generations
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(TurnError::SecondModelTurn);
        }
        runtime.generate(request).await.map_err(TurnError::Runtime)
    }

    fn generation_request(
        &self,
        protocol: SelectedProtocol,
        prompt: &str,
    ) -> Result<GenerationRequest, TurnError> {
        let exposed = self.exposed_tools();
        let (system, tools, response_format) = match protocol {
            SelectedProtocol::Native => (
                NATIVE_SYSTEM.to_owned(),
                self.native_tools(&exposed)?,
                ResponseFormat::Text,
            ),
            SelectedProtocol::StructuredJson {
                json_mode_confirmed: true,
            } => (
                json_system(&catalog(&exposed)?)?,
                Vec::new(),
                ResponseFormat::Json,
            ),
            // Unconfirmed JSON mode stays text. The bounded loop requests JSON separately.
            // This single-turn path must not follow that change.
            SelectedProtocol::StructuredJson {
                json_mode_confirmed: false,
            } => (
                json_system(&catalog(&exposed)?)?,
                Vec::new(),
                ResponseFormat::Text,
            ),
        };
        GenerationRequest::try_new(
            &self.settings.model,
            vec![lca_model_runtime::Message::user(prompt)],
            GenerationOptions {
                system: Some(system),
                tools,
                response_format,
                max_tokens: Some(self.settings.max_tokens),
                timeout: Some(self.settings.timeout),
                context_tokens: Some(self.settings.context_tokens),
                ..GenerationOptions::default()
            },
        )
        .map_err(TurnError::Runtime)
    }

    fn exposed_tools(&self) -> Vec<&RegisteredTool> {
        self.registry
            .iter()
            .filter(|tool| self.advertise(tool))
            .collect()
    }

    fn advertise(&self, tool: &RegisteredTool) -> bool {
        if !matches!(authorize_proposal(tool), PolicyDecision::ProposalAllowed) {
            return false;
        }
        match tool.permission() {
            PermissionCategory::Diagnostic => false,
            PermissionCategory::WorkspaceRead => self.limits.read_enabled(),
            PermissionCategory::WorkspaceMutation => self.limits.allows_prepare(),
        }
    }

    fn native_tools(&self, exposed: &[&RegisteredTool]) -> Result<Vec<ToolDefinition>, TurnError> {
        exposed
            .iter()
            .map(|tool| {
                ToolDefinition::try_new(tool.name(), tool.description(), tool.schema().clone())
                    .map_err(TurnError::Runtime)
            })
            .collect()
    }

    fn dispatch_all(
        &self,
        batch: &lca_tools::ToolCallBatch,
    ) -> Result<Vec<ExecutedAction>, TurnError> {
        let mut done = Vec::with_capacity(batch.len());
        for (index, action) in batch.actions().iter().enumerate() {
            match crate::dispatch_validated(action, &self.sandbox, &self.limits) {
                Ok(outcome) => done.push(executed(action, outcome)),
                Err(error) => {
                    return Err(TurnError::Execution {
                        index,
                        error,
                        prior: done,
                    });
                }
            }
        }
        Ok(done)
    }
}

pub(crate) fn record_executed(action: &ValidatedAction, outcome: FsOutcome) -> ExecutedAction {
    executed(action, outcome)
}

fn executed(action: &ValidatedAction, outcome: FsOutcome) -> ExecutedAction {
    ExecutedAction {
        id: action.id().get(),
        tool: action.name().to_owned(),
        source: action.source(),
        outcome,
    }
}

fn catalog(tools: &[&RegisteredTool]) -> Result<String, TurnError> {
    let entries: Vec<Value> = tools
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name(),
                "description": tool.description(),
                "parameters": tool.schema(),
            })
        })
        .collect();
    serde_json::to_string(&entries)
        .map_err(|_| TurnError::Runtime(RuntimeError::invalid("tool catalog could not be encoded")))
}

fn json_system(catalog_json: &str) -> Result<String, TurnError> {
    let system = format!(
        "Return only one JSON object and no other text. \
Use protocol_version 1. \
The object may contain only protocol_version and actions. \
Each action may contain only tool and arguments. \
Do not use markdown. Do not invent tools. Do not add fields. \
Do not call a tool only because it is listed. \
Workspace tools are only for information that is actually in this project. \
A general knowledge question uses an empty actions array. \
If no tool is required, return protocol_version 1 and an empty actions array. \
An approval-required tool prepares a change and does not write. \
You cannot approve a write. \
This turn ends after your response.\n\
Tools: {catalog_json}"
    );
    if system.chars().count() > lca_model_runtime::MAX_MESSAGE_CHARS {
        return Err(TurnError::Runtime(RuntimeError::invalid(
            "tool catalog does not fit in the system instructions",
        )));
    }
    Ok(system)
}

fn proposed_calls(
    protocol: SelectedProtocol,
    response: &GenerationResponse,
) -> Result<Vec<(String, Value)>, TurnError> {
    match protocol {
        SelectedProtocol::Native => Ok(response
            .tool_calls()
            .iter()
            .map(|call| (call.name().to_owned(), call.arguments().clone()))
            .collect()),
        SelectedProtocol::StructuredJson { .. } => {
            let actions = parse_action_document(response.text()).map_err(TurnError::Json)?;
            Ok(actions
                .into_iter()
                .map(|action| (action.tool().to_owned(), action.arguments().clone()))
                .collect())
        }
    }
}

/// Classifies a response for diagnostics.
///
/// Native execution still uses only [`GenerationResponse::tool_calls`]. JSON execution
/// still uses only [`parse_action_document`]. This function does not change either path.
#[must_use]
pub fn classify_response(
    protocol: SelectedProtocol,
    response: &GenerationResponse,
) -> (ResponseClass, Option<&'static str>) {
    match protocol {
        SelectedProtocol::Native => classify_native(response),
        SelectedProtocol::StructuredJson { .. } => {
            if looks_like_pseudo_tool_call(response.text()) {
                (ResponseClass::PseudoToolCallText, Some(PSEUDO_DIAGNOSTIC))
            } else {
                (ResponseClass::PlainText, None)
            }
        }
    }
}

fn classify_native(response: &GenerationResponse) -> (ResponseClass, Option<&'static str>) {
    if !response.tool_calls().is_empty() {
        return (ResponseClass::NativeToolCall, None);
    }
    if looks_like_pseudo_tool_call(response.text()) {
        return (ResponseClass::PseudoToolCallText, Some(PSEUDO_DIAGNOSTIC));
    }
    if json_tool_shape(response.text()) {
        return (
            ResponseClass::InvalidNativeResponse,
            Some(INVALID_NATIVE_DIAGNOSTIC),
        );
    }
    (ResponseClass::PlainText, None)
}

fn looks_like_pseudo_tool_call(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("<tool_call")
        || lower.contains("</tool_call>")
        || lower.contains("<function=")
        || lower.contains("<parameter=")
}

fn json_tool_shape(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.len() > 64 * 1024 {
        return false;
    }
    let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
        return false;
    };
    match value {
        Value::Object(map) => object_is_toolish(&map),
        Value::Array(items) => items.iter().any(|item| {
            item.as_object()
                .is_some_and(|map| map.contains_key("tool") || map.contains_key("function"))
        }),
        _ => false,
    }
}

fn object_is_toolish(map: &serde_json::Map<String, Value>) -> bool {
    map.contains_key("tool")
        || map.contains_key("tool_calls")
        || map.contains_key("actions")
        || map.contains_key("function")
        || map.contains_key("protocol_version")
        || (map.contains_key("name") && map.contains_key("arguments"))
}

fn source_of(protocol: SelectedProtocol) -> ActionSource {
    match protocol {
        SelectedProtocol::Native => ActionSource::Native,
        SelectedProtocol::StructuredJson { .. } => ActionSource::StructuredJson,
    }
}

fn fail(task: &mut AgentTask, now: SystemTime, error: TurnError) -> TurnError {
    tracing::debug!(
        error_kind = error.kind(),
        status = task.status().as_str(),
        "single-turn agent failed"
    );
    if task.status().can_transition(AgentStatus::Failed) {
        match task.transition(AgentStatus::Failed, now) {
            Ok(()) => error,
            Err(lifecycle) => TurnError::Lifecycle(lifecycle),
        }
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    use async_trait::async_trait;
    use lca_model_runtime::{
        CapabilityParts, CapabilityStatus, GenerationStream, ModelCapabilities, RawToolCall,
    };
    use lca_tools::FsLimitValues;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path =
                std::env::temp_dir().join(format!("lca-turn-{}-{nanos}-{id}", std::process::id()));
            std::fs::create_dir_all(&path).expect("temp");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct MockRuntime {
        tools: CapabilityStatus,
        json_mode: CapabilityStatus,
        response: GenerationResponse,
        fail: bool,
        generate_calls: AtomicUsize,
        capability_calls: AtomicUsize,
        stream_calls: AtomicUsize,
        last: Mutex<Option<GenerationRequest>>,
    }

    #[async_trait]
    impl ModelRuntime for MockRuntime {
        async fn generate(
            &self,
            request: GenerationRequest,
        ) -> Result<GenerationResponse, RuntimeError> {
            request.validate()?;
            self.generate_calls.fetch_add(1, Ordering::SeqCst);
            *self.last.lock().expect("request lock") = Some(request);
            if self.fail {
                Err(RuntimeError::invalid("backend refused"))
            } else {
                Ok(self.response.clone())
            }
        }

        async fn generate_stream(
            &self,
            _request: GenerationRequest,
        ) -> Result<GenerationStream, RuntimeError> {
            self.stream_calls.fetch_add(1, Ordering::SeqCst);
            Err(RuntimeError::invalid("single-turn must not stream"))
        }

        async fn capabilities(&self, model: &str) -> Result<ModelCapabilities, RuntimeError> {
            self.capability_calls.fetch_add(1, Ordering::SeqCst);
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

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(10)
    }

    fn settings(preference: ProtocolPreference, max_actions: usize) -> TurnSettings {
        TurnSettings {
            model: "lca-agent".to_owned(),
            preference,
            max_tokens: 128,
            timeout: Duration::from_secs(5),
            context_tokens: 2048,
            max_actions,
        }
    }

    fn limits(read: bool, write: bool) -> FsLimits {
        FsLimits::try_new(FsLimitValues {
            read_enabled: read,
            write_enabled: write,
            max_file_size_bytes: 1024 * 1024,
            max_response_bytes: 256 * 1024,
            max_directory_entries: 1000,
            max_search_matches: 100,
            max_search_files: 1000,
            max_search_total_bytes: 32 * 1024 * 1024,
        })
        .expect("limits")
    }

    fn controller(
        root: &Path,
        preference: ProtocolPreference,
        max_actions: usize,
        read: bool,
        write: bool,
    ) -> SingleTurnAgentController {
        SingleTurnAgentController::new(
            ToolRegistry::workspace().expect("registry"),
            WorkspaceSandbox::new(root).expect("sandbox"),
            limits(read, write),
            settings(preference, max_actions),
        )
        .expect("controller")
    }

    fn response(calls: Vec<RawToolCall>, text: &str) -> GenerationResponse {
        GenerationResponse::complete("lca-agent", text, None, None, None).with_tool_calls(calls)
    }

    fn read_call(path: &str) -> RawToolCall {
        RawToolCall::new("read_file", json!({"path": path}))
    }

    fn mock(
        tools: CapabilityStatus,
        json_mode: CapabilityStatus,
        body: GenerationResponse,
    ) -> MockRuntime {
        MockRuntime {
            tools,
            json_mode,
            response: body,
            fail: false,
            generate_calls: AtomicUsize::new(0),
            capability_calls: AtomicUsize::new(0),
            stream_calls: AtomicUsize::new(0),
            last: Mutex::new(None),
        }
    }

    fn assert_one_turn(runtime: &MockRuntime) {
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.capability_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.stream_calls.load(Ordering::SeqCst), 0);
    }

    fn request_of(runtime: &MockRuntime) -> GenerationRequest {
        runtime.last.lock().expect("lock").clone().expect("request")
    }

    #[tokio::test]
    async fn auto_for_the_registered_model_selects_json_without_a_second_protocol() {
        let root = TempDir::new();
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(Vec::new(), r#"{"protocol_version":1,"actions":[]}"#),
        );
        let agent = SingleTurnAgentController::new(
            ToolRegistry::workspace().expect("registry"),
            WorkspaceSandbox::new(&root.0).expect("sandbox"),
            limits(true, true),
            TurnSettings {
                model: "lca-30b-agent".to_owned(),
                ..settings(ProtocolPreference::Auto, 8)
            },
        )
        .expect("controller");
        let report = agent
            .run(&runtime, "Was ist Ownership?", now())
            .await
            .expect("turn");
        assert_one_turn(&runtime);
        assert_eq!(report.protocol().as_str(), "json");
        assert!(report.actions().is_empty());
        let request = request_of(&runtime);
        assert!(request.tools().is_empty());
        assert_eq!(request.response_format(), ResponseFormat::Text);
        assert!(!report.protocol().json_mode_confirmed());
        let system = request.system().expect("system");
        assert!(system.contains("protocol_version 1"), "{system}");
        assert!(!system.contains("final_answer"), "{system}");
        assert!(!system.contains("protocol_version is always 2"), "{system}");
    }

    #[tokio::test]
    async fn native_read_uses_registry_schemas_and_one_generation() {
        let root = TempDir::new();
        std::fs::write(root.0.join("notes.txt"), "alpha\n").expect("seed");
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(
                vec![read_call("notes.txt")],
                "<tool_call>read_file</tool_call>",
            ),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 8, true, true);
        let report = agent
            .run(&runtime, "Lies notes.txt", now())
            .await
            .expect("turn");
        assert_one_turn(&runtime);
        assert_eq!(report.model_calls(), 1);
        assert_eq!(report.protocol().as_str(), "native");
        assert_eq!(report.actions().len(), 1);
        assert_eq!(report.actions()[0].tool(), "read_file");
        assert_eq!(report.actions()[0].source(), ActionSource::Native);
        let FsOutcome::Read(file) = report.actions()[0].outcome() else {
            panic!("read");
        };
        assert_eq!(file.content, "alpha\n");
        assert!(!file.truncated);

        let request = request_of(&runtime);
        assert_eq!(request.messages().len(), 1);
        assert_eq!(request.messages()[0].content(), "Lies notes.txt");
        assert_eq!(request.response_format(), ResponseFormat::Text);
        let registry = ToolRegistry::workspace().expect("registry");
        let names: Vec<&str> = request.tools().iter().map(ToolDefinition::name).collect();
        assert_eq!(
            names,
            vec!["list_directory", "read_file", "search_files", "apply_patch"]
        );
        for tool in request.tools() {
            assert_eq!(
                tool.parameters(),
                registry.get(tool.name()).expect("registered").schema()
            );
            assert_eq!(
                tool.description(),
                registry.get(tool.name()).expect("registered").description()
            );
        }
        assert!(!request.system().unwrap_or("").contains("diagnostic_echo"));
        assert_eq!(runtime.stream_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn prose_and_json_text_are_not_native_tool_calls() {
        let root = TempDir::new();
        std::fs::write(root.0.join("secret.txt"), "SENTINEL_DO_NOT_LEAK").expect("secret");
        let document = r#"{"protocol_version":1,"actions":[{"tool":"read_file","arguments":{"path":"secret.txt"}}]}"#;
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Confirmed,
            response(Vec::new(), document),
        );
        let agent = controller(&root.0, ProtocolPreference::Auto, 8, true, true);
        let report = agent
            .run(&runtime, "read the secret", now())
            .await
            .expect("text");
        assert_one_turn(&runtime);
        assert!(report.actions().is_empty());
        assert_eq!(report.text(), document);
        assert!(!report.text().contains("SENTINEL_DO_NOT_LEAK"));
        assert_eq!(request_of(&runtime).response_format(), ResponseFormat::Text);
    }

    #[tokio::test]
    async fn json_fallback_ignores_native_calls_and_rejects_markdown() {
        let root = TempDir::new();
        std::fs::write(root.0.join("notes.txt"), "alpha\n").expect("notes");
        std::fs::write(root.0.join("secret.txt"), "SENTINEL_DO_NOT_LEAK").expect("secret");
        let document = r#"{"protocol_version":1,"actions":[{"tool":"read_file","arguments":{"path":"notes.txt"}}]}"#;
        let runtime = mock(
            CapabilityStatus::NotReported,
            CapabilityStatus::Confirmed,
            response(vec![read_call("secret.txt")], document),
        );
        let agent = controller(&root.0, ProtocolPreference::StructuredJson, 8, true, true);
        let report = agent
            .run(&runtime, "Lies notes.txt", now())
            .await
            .expect("json");
        assert_one_turn(&runtime);
        assert_eq!(report.protocol().as_str(), "json");
        assert!(report.protocol().json_mode_confirmed());
        assert_eq!(report.actions().len(), 1);
        assert_eq!(report.actions()[0].source(), ActionSource::StructuredJson);
        let FsOutcome::Read(file) = report.actions()[0].outcome() else {
            panic!("read");
        };
        assert_eq!(file.content, "alpha\n");
        let request = request_of(&runtime);
        assert!(request.tools().is_empty());
        assert_eq!(request.response_format(), ResponseFormat::Json);
        let schema = serde_json::to_string(
            ToolRegistry::workspace()
                .expect("registry")
                .get("read_file")
                .expect("read")
                .schema(),
        )
        .expect("schema");
        let system = request.system().expect("system");
        assert!(system.contains(&schema), "{system}");
        assert!(system.contains("protocol_version 1"));
        assert!(!system.contains("diagnostic_echo"));
        assert!(!system.contains("execute_command"));

        let runtime = mock(
            CapabilityStatus::Unknown,
            CapabilityStatus::Unknown,
            response(
                Vec::new(),
                "```json\n{\"protocol_version\":1,\"actions\":[]}\n```",
            ),
        );
        let agent = controller(&root.0, ProtocolPreference::StructuredJson, 8, true, true);
        let error = agent
            .run(&runtime, "Lies notes.txt", now())
            .await
            .expect_err("markdown");
        assert_eq!(error.kind(), "markdown");
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 1);
        assert!(error.prior_actions().is_empty());
        let request = request_of(&runtime);
        assert_eq!(request.response_format(), ResponseFormat::Text);
        assert!(request.tools().is_empty());
    }

    #[tokio::test]
    async fn native_response_does_not_fall_back_to_json() {
        let root = TempDir::new();
        std::fs::write(root.0.join("notes.txt"), "alpha\n").expect("notes");
        std::fs::write(root.0.join("secret.txt"), "SENTINEL_DO_NOT_LEAK").expect("secret");
        let document = r#"{"protocol_version":1,"actions":[{"tool":"read_file","arguments":{"path":"secret.txt"}}]}"#;
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Confirmed,
            response(vec![read_call("notes.txt")], document),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 8, true, true);
        let report = agent
            .run(&runtime, "read notes", now())
            .await
            .expect("native");
        assert_one_turn(&runtime);
        let FsOutcome::Read(file) = report.actions()[0].outcome() else {
            panic!("read");
        };
        assert_eq!(file.content, "alpha\n");
        assert_eq!(report.actions()[0].source(), ActionSource::Native);

        let second = agent
            .run(&runtime, "again", now())
            .await
            .expect_err("second");
        assert_eq!(second.kind(), "second_model_turn");
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.capability_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn invalid_batches_are_not_executed() {
        let root = TempDir::new();
        std::fs::write(root.0.join("secret.txt"), "SENTINEL_DO_NOT_LEAK").expect("secret");
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(
                vec![RawToolCall::new(
                    "execute_command",
                    json!({"command": "SENTINEL_DO_NOT_LEAK"}),
                )],
                "",
            ),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 8, true, true);
        let error = agent
            .run(&runtime, "run", now())
            .await
            .expect_err("unknown");
        assert_eq!(error.kind(), "unknown_tool");
        assert!(!error.to_string().contains("SENTINEL_DO_NOT_LEAK"));
        assert!(error.prior_actions().is_empty());
        assert_one_turn(&runtime);

        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(vec![read_call("secret.txt"), read_call("secret.txt")], ""),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 1, true, true);
        let error = agent.run(&runtime, "run", now()).await.expect_err("limit");
        assert_eq!(error.kind(), "action_limit");
        assert!(matches!(
            error,
            TurnError::ActionLimit {
                limit: 1,
                actual: 2
            }
        ));
        assert!(!error.to_string().contains("SENTINEL_DO_NOT_LEAK"));
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 1);

        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(
                vec![
                    read_call("secret.txt"),
                    RawToolCall::new("execute_command", json!({})),
                ],
                "",
            ),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 8, true, true);
        let error = agent.run(&runtime, "run", now()).await.expect_err("batch");
        assert_eq!(error.kind(), "unknown_tool");
        assert!(error.prior_actions().is_empty());
        assert!(!error.to_string().contains("SENTINEL_DO_NOT_LEAK"));

        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(vec![RawToolCall::new("read_file", json!({}))], ""),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 8, true, true);
        let error = agent.run(&runtime, "run", now()).await.expect_err("schema");
        assert_eq!(error.kind(), "invalid_arguments");
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_tool_error_stops_the_batch_without_another_model_call() {
        let root = TempDir::new();
        std::fs::write(root.0.join("notes.txt"), "alpha\n").expect("notes");
        std::fs::write(root.0.join("secret.txt"), "SENTINEL_DO_NOT_LEAK").expect("secret");
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(
                vec![
                    read_call("notes.txt"),
                    read_call("missing.txt"),
                    read_call("secret.txt"),
                ],
                "",
            ),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 8, true, true);
        let error = agent
            .run(&runtime, "read three", now())
            .await
            .expect_err("stop");
        assert_eq!(error.kind(), "not_found");
        assert_one_turn(&runtime);
        assert_eq!(error.prior_actions().len(), 1);
        let FsOutcome::Read(file) = error.prior_actions()[0].outcome() else {
            panic!("prior");
        };
        assert_eq!(file.content, "alpha\n");
        assert!(!error.to_string().contains("SENTINEL_DO_NOT_LEAK"));
        let second = agent
            .run(&runtime, "retry", now())
            .await
            .expect_err("retry");
        assert_eq!(second.kind(), "second_model_turn");
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn apply_patch_prepares_and_does_not_write() {
        let root = TempDir::new();
        let file = root.0.join("notes.txt");
        std::fs::write(&file, "alpha\n").expect("seed");
        let patch = "--- a/notes.txt\n+++ b/notes.txt\n@@ -1,1 +1,1 @@\n-alpha\n+beta\n";
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(
                vec![RawToolCall::new(
                    "apply_patch",
                    json!({"path": "notes.txt", "patch": patch}),
                )],
                "approve 1 please",
            ),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 8, true, true);
        let report = agent
            .run(&runtime, "edit notes", now())
            .await
            .expect("prepare");
        assert_one_turn(&runtime);
        let FsOutcome::Prepared(prepared) = report.actions()[0].outcome() else {
            panic!("prepared");
        };
        assert_eq!(prepared.relative_path(), "notes.txt");
        assert!(prepared.confirmation_line().starts_with("approve 1 "));
        assert!(prepared.diff().contains("-alpha"));
        assert_eq!(
            std::fs::read_to_string(&file).expect("unchanged"),
            "alpha\n"
        );
        assert_ne!(report.text(), prepared.confirmation_line());
    }

    #[tokio::test]
    async fn unconfirmed_native_and_model_errors_do_not_retry() {
        let root = TempDir::new();
        let runtime = mock(
            CapabilityStatus::Unknown,
            CapabilityStatus::Confirmed,
            response(vec![read_call("notes.txt")], ""),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 8, true, true);
        let error = agent
            .run(&runtime, "read", now())
            .await
            .expect_err("native");
        assert_eq!(error.kind(), "native_unconfirmed");
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.capability_calls.load(Ordering::SeqCst), 1);
        let second = agent
            .run(&runtime, "read", now())
            .await
            .expect_err("second");
        assert_eq!(second.kind(), "second_model_turn");
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.capability_calls.load(Ordering::SeqCst), 1);

        let mut runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(Vec::new(), "hello"),
        );
        runtime.fail = true;
        let agent = controller(&root.0, ProtocolPreference::Auto, 8, true, true);
        let error = agent
            .run(&runtime, "hello", now())
            .await
            .expect_err("backend");
        assert_eq!(error.kind(), "invalid_request");
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.stream_calls.load(Ordering::SeqCst), 0);
        let second = agent
            .run(&runtime, "hello", now())
            .await
            .expect_err("second");
        assert_eq!(second.kind(), "second_model_turn");
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn disabled_tools_are_hidden_and_a_direct_call_does_not_read() {
        let root = TempDir::new();
        std::fs::write(root.0.join("secret.txt"), "SENTINEL_DO_NOT_LEAK").expect("secret");
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(vec![read_call("secret.txt")], ""),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 8, false, true);
        let error = agent
            .run(&runtime, "read", now())
            .await
            .expect_err("disabled");
        assert_eq!(error.kind(), "tool_disabled");
        assert!(!error.to_string().contains("SENTINEL_DO_NOT_LEAK"));
        let request = request_of(&runtime);
        let names: Vec<&str> = request.tools().iter().map(ToolDefinition::name).collect();
        assert_eq!(names, vec!["apply_patch"]);

        let runtime = mock(
            CapabilityStatus::NotReported,
            CapabilityStatus::Unknown,
            response(Vec::new(), r#"{"protocol_version":1,"actions":[]}"#),
        );
        let agent = controller(&root.0, ProtocolPreference::Auto, 8, false, false);
        let report = agent.run(&runtime, "just text", now()).await.expect("text");
        assert!(report.actions().is_empty());
        assert!(request_of(&runtime).tools().is_empty());
        assert!(
            !request_of(&runtime)
                .system()
                .unwrap_or("")
                .contains("read_file")
        );
    }

    #[tokio::test]
    async fn the_configured_budget_cannot_raise_the_protocol_limit() {
        let root = TempDir::new();
        let built = SingleTurnAgentController::new(
            ToolRegistry::workspace().expect("registry"),
            WorkspaceSandbox::new(&root.0).expect("sandbox"),
            limits(true, true),
            settings(ProtocolPreference::Native, 0),
        );
        let Err(error) = built else {
            panic!("zero");
        };
        assert_eq!(error.kind(), "invalid_action_limit");

        let calls = (0..9).map(|_| read_call("notes.txt")).collect();
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(calls, ""),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 100, true, true);
        assert_eq!(agent.max_actions(), MAX_ACTIONS);
        let error = agent
            .run(&runtime, "too many", now())
            .await
            .expect_err("nine");
        assert_eq!(error.kind(), "action_limit");
        assert!(matches!(
            error,
            TurnError::ActionLimit {
                limit: 8,
                actual: 9
            }
        ));
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_empty_prompt_does_not_call_the_runtime() {
        let root = TempDir::new();
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Confirmed,
            response(Vec::new(), "nope"),
        );
        let agent = controller(&root.0, ProtocolPreference::Auto, 8, true, true);
        let error = agent.run(&runtime, "   ", now()).await.expect_err("empty");
        assert_eq!(error.kind(), "empty_prompt");
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.capability_calls.load(Ordering::SeqCst), 0);
        assert_eq!(runtime.stream_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn diagnostic_echo_is_not_advertised_and_is_not_executed() {
        let root = TempDir::new();
        std::fs::write(root.0.join("secret.txt"), "SENTINEL_DO_NOT_LEAK").expect("secret");
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(
                vec![RawToolCall::new(
                    "diagnostic_echo",
                    json!({"message": "SENTINEL_DO_NOT_LEAK"}),
                )],
                "",
            ),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 8, true, true);
        let report = agent.run(&runtime, "echo", now()).await.expect("echo");
        assert_one_turn(&runtime);
        assert_eq!(report.actions()[0].tool(), "diagnostic_echo");
        assert!(matches!(
            report.actions()[0].outcome(),
            FsOutcome::NotExecuted { .. }
        ));
        assert!(!report.text().contains("SENTINEL_DO_NOT_LEAK"));
        let request = request_of(&runtime);
        assert!(
            request
                .tools()
                .iter()
                .all(|tool| tool.name() != "diagnostic_echo")
        );
    }

    #[tokio::test]
    async fn several_calls_keep_order() {
        let root = TempDir::new();
        std::fs::create_dir(root.0.join("src")).expect("src");
        std::fs::write(root.0.join("src").join("lib.rs"), "fn main() {}\n").expect("lib");
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(
                vec![
                    RawToolCall::new("list_directory", json!({"path": "."})),
                    read_call("src/lib.rs"),
                ],
                "",
            ),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 4, true, true);
        let report = agent.run(&runtime, "look", now()).await.expect("batch");
        assert_eq!(report.actions().len(), 2);
        assert_eq!(report.actions()[0].tool(), "list_directory");
        assert_eq!(report.actions()[0].id(), 1);
        assert_eq!(report.actions()[1].tool(), "read_file");
        assert_eq!(report.actions()[1].id(), 2);
        assert!(matches!(
            report.actions()[0].outcome(),
            FsOutcome::Listed(_)
        ));
        let FsOutcome::Read(file) = report.actions()[1].outcome() else {
            panic!("read");
        };
        assert!(file.content.contains("fn main"));
        assert_eq!(agent.generations(), 1);
    }

    #[tokio::test]
    async fn the_system_prompt_asks_for_the_tool_interface_and_plain_answers() {
        let root = TempDir::new();
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(
                Vec::new(),
                "Ownership ist ein Regelwerk. Borrowing ist die zweite Regel.",
            ),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 8, true, true);
        let report = agent
            .run(&runtime, "Erkläre Rust Ownership in zwei Sätzen.", now())
            .await
            .expect("text");
        assert_eq!(report.response_class(), ResponseClass::PlainText);
        assert!(report.actions().is_empty());
        assert!(report.diagnostic().is_none());
        assert_one_turn(&runtime);
        let request = request_of(&runtime);
        let system = request.system().expect("system").to_owned();
        for phrase in [
            "tool interface attached to this request",
            "Do not write a tool call as XML, Markdown, or pseudocode",
            "only because it is available",
            "general knowledge question does not need a workspace tool",
            "ordinary text",
            "This turn ends after your response",
        ] {
            assert!(system.contains(phrase), "{phrase} missing in {system}");
        }
    }

    #[tokio::test]
    async fn pseudo_tool_call_text_is_not_executed_and_is_not_retried() {
        let root = TempDir::new();
        std::fs::write(root.0.join("secret.txt"), "SENTINEL_DO_NOT_LEAK").expect("secret");
        let text = "\
<function=search_files>
<parameter=path>
crates
</parameter>
<parameter=query>
ModelRuntime
</parameter>
</function>
</tool_call>";
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Confirmed,
            response(Vec::new(), text),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 8, true, true);
        let report = agent
            .run(
                &runtime,
                "Suche im Verzeichnis crates nach ModelRuntime.",
                now(),
            )
            .await
            .expect("text");
        assert_one_turn(&runtime);
        assert!(report.actions().is_empty());
        assert_eq!(report.response_class(), ResponseClass::PseudoToolCallText);
        assert!(report.diagnostic().is_some());
        assert!(!report.text().contains("SENTINEL_DO_NOT_LEAK"));
        let second = agent
            .run(&runtime, "again", now())
            .await
            .expect_err("second");
        assert_eq!(second.kind(), "second_model_turn");
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.stream_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn json_in_native_mode_is_classified_and_not_executed() {
        let root = TempDir::new();
        std::fs::write(root.0.join("secret.txt"), "SENTINEL_DO_NOT_LEAK").expect("secret");
        let document = r#"{"protocol_version":1,"actions":[{"tool":"read_file","arguments":{"path":"secret.txt"}}]}"#;
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Confirmed,
            response(Vec::new(), document),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 8, true, true);
        let report = agent
            .run(&runtime, "Lies secret.txt", now())
            .await
            .expect("text");
        assert!(report.actions().is_empty());
        assert_eq!(
            report.response_class(),
            ResponseClass::InvalidNativeResponse
        );
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 1);
        assert!(!report.text().contains("SENTINEL_DO_NOT_LEAK"));
    }

    #[tokio::test]
    async fn a_structured_read_of_lca_toml_is_denied_without_leaking_bytes() {
        let root = TempDir::new();
        std::fs::write(root.0.join("lca.toml"), "SENTINEL_DO_NOT_LEAK\n").expect("secret");
        std::fs::write(root.0.join("Cargo.toml"), "[package]\n").expect("cargo");
        let runtime = mock(
            CapabilityStatus::Confirmed,
            CapabilityStatus::Unknown,
            response(vec![read_call("lca.toml")], ""),
        );
        let agent = controller(&root.0, ProtocolPreference::Native, 8, true, true);
        let error = agent
            .run(&runtime, "Lies lca.toml.", now())
            .await
            .expect_err("denied");
        assert_eq!(error.kind(), "privacy_denied");
        assert!(!error.to_string().contains("SENTINEL_DO_NOT_LEAK"));
        assert!(error.prior_actions().is_empty());
        assert_one_turn(&runtime);
        let second = agent
            .run(&runtime, "retry", now())
            .await
            .expect_err("second");
        assert_eq!(second.kind(), "second_model_turn");
        assert_eq!(runtime.generate_calls.load(Ordering::SeqCst), 1);
    }
}
