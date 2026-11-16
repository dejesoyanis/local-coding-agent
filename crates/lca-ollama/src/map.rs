use std::time::Duration;

use lca_model_runtime::{
    CapabilityParts, CapabilityStatus, FinishReason, GenerationEvent, GenerationMetadata,
    GenerationRequest, GenerationResponse, MAX_NATIVE_TOOL_CALLS, ModelCapabilities, RawToolCall,
    ResponseFormat, RuntimeError, TimingMetadata, TokenUsage,
};
use serde::Deserialize;
use serde::Serialize;
use serde_json::{Map, Value};

const MAX_ERROR_CHARS: usize = 512;

#[derive(Debug, Serialize)]
struct ChatPayload {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<ChatOptions>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<OllamaTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct OllamaTool {
    #[serde(rename = "type")]
    kind: &'static str,
    function: OllamaFunction,
}

#[derive(Debug, Serialize)]
struct OllamaFunction {
    name: String,
    description: String,
    parameters: Value,
}

#[derive(Debug, Serialize)]
struct ChatOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_k: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repeat_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_ctx: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ChatChunk {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    message: Option<ChatMessageOut>,
    #[serde(default)]
    done: Option<bool>,
    #[serde(default)]
    done_reason: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    total_duration: Option<u64>,
    #[serde(default)]
    load_duration: Option<u64>,
    #[serde(default)]
    prompt_eval_count: Option<u64>,
    #[serde(default)]
    prompt_eval_duration: Option<u64>,
    #[serde(default)]
    eval_count: Option<u64>,
    #[serde(default)]
    eval_duration: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ChatMessageOut {
    #[serde(default)]
    content: Option<String>,
    /// Kept as raw JSON so a streaming frame with an unexpected shape still yields text.
    /// Non-streaming responses interpret this value separately and do not repair it.
    #[serde(default)]
    tool_calls: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ShowResponse {
    #[serde(default)]
    capabilities: Option<Vec<String>>,
    #[serde(default)]
    details: Option<ShowDetails>,
    #[serde(default)]
    model_info: Option<Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
struct ShowDetails {
    #[serde(default)]
    family: Option<String>,
    #[serde(default)]
    parameter_size: Option<String>,
    #[serde(default)]
    quantization_level: Option<String>,
}

/// Serializes a validated chat request. Ollama field names stay inside this crate.
pub(crate) fn chat_payload(
    request: &GenerationRequest,
    stream: bool,
) -> Result<Value, RuntimeError> {
    request.validate()?;
    let payload = ChatPayload {
        model: request.model().to_owned(),
        messages: mapped_messages(request),
        stream,
        options: options_of(request),
        tools: ollama_tools(request),
        format: json_format(request),
    };
    serde_json::to_value(payload)
        .map_err(|_| RuntimeError::invalid("generation request could not be encoded"))
}

/// Converts one non-streaming chat JSON document into a runtime response.
pub(crate) fn response_from_chat_json(
    bytes: &[u8],
    fallback_model: &str,
) -> Result<GenerationResponse, RuntimeError> {
    let chunk = parse_chunk(bytes)?;
    if let Some(message) = chunk.error.as_deref() {
        return Err(error_from_backend_message(message, fallback_model, None));
    }
    if chunk.done != Some(true) {
        return Err(RuntimeError::protocol(
            "non-streaming response was not terminal",
        ));
    }
    let metadata = metadata_from(&chunk, fallback_model);
    let tool_calls = match chunk.message.as_ref() {
        Some(message) => tool_calls_from(message.tool_calls.as_ref())?,
        None => Vec::new(),
    };
    Ok(GenerationResponse::complete(
        metadata.model(),
        content_of(&chunk),
        metadata.finish_reason().cloned(),
        metadata.usage(),
        metadata.timing(),
    )
    .with_tool_calls(tool_calls))
}

/// Converts one NDJSON frame into zero or more events, or a terminal stream error.
pub(crate) fn interpret_line(
    line: &str,
    fallback_model: &str,
) -> Result<Vec<GenerationEvent>, RuntimeError> {
    let chunk = parse_chunk(line.as_bytes())?;
    if let Some(message) = chunk.error.as_deref() {
        return Err(error_from_backend_message(message, fallback_model, None));
    }
    let mut events = Vec::new();
    // Tool calls are not streamed. A frame may still carry a `tool_calls` field; it is not
    // turned into an event and it is not parsed out of the text.
    let content = content_of(&chunk);
    if !content.is_empty() {
        events.push(GenerationEvent::TextDelta(content));
    }
    if chunk.done == Some(true) {
        events.push(GenerationEvent::Completed(metadata_from(
            &chunk,
            fallback_model,
        )));
    }
    Ok(events)
}

/// Converts `POST /api/show` JSON into a capability report.
pub(crate) fn capabilities_from_show(
    model: &str,
    bytes: &[u8],
) -> Result<ModelCapabilities, RuntimeError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(RuntimeError::protocol("response body was empty"));
    }
    let show: ShowResponse = serde_json::from_slice(bytes)
        .map_err(|_| RuntimeError::protocol("model information was not valid JSON"))?;
    Ok(map_show(model, show))
}

/// Classifies an unsuccessful HTTP response without copying a raw body into the error.
pub(crate) fn error_from_http(
    status: u16,
    body: &[u8],
    model: &str,
    timeout: Duration,
) -> RuntimeError {
    if matches!(status, 408 | 504) {
        return RuntimeError::timeout(timeout, None);
    }
    if status == 404 {
        return RuntimeError::model_not_found(model, json_error_field(body));
    }
    if let Some(message) = json_error_field(body) {
        return error_from_backend_message(&message, model, Some(status));
    }
    if matches!(status, 400 | 422) {
        return RuntimeError::invalid(format!("HTTP {status}"));
    }
    RuntimeError::backend(Some(status), format!("HTTP {status}"))
}

fn mapped_messages(request: &GenerationRequest) -> Vec<ChatMessage> {
    let mut messages = Vec::new();
    if let Some(system) = request.system() {
        messages.push(ChatMessage {
            role: "system".to_owned(),
            content: system.to_owned(),
        });
    }
    for message in request.messages() {
        messages.push(ChatMessage {
            role: message.role().as_str().to_owned(),
            content: message.content().to_owned(),
        });
    }
    messages
}

fn ollama_tools(request: &GenerationRequest) -> Vec<OllamaTool> {
    request
        .tools()
        .iter()
        .map(|tool| OllamaTool {
            kind: "function",
            function: OllamaFunction {
                name: tool.name().to_owned(),
                description: tool.description().to_owned(),
                parameters: tool.parameters().clone(),
            },
        })
        .collect()
}

fn json_format(request: &GenerationRequest) -> Option<&'static str> {
    match request.response_format() {
        ResponseFormat::Json => Some("json"),
        ResponseFormat::Text => None,
    }
}

/// Interprets native `tool_calls`. Text markers such as `<tool_call>` are not consulted.
fn tool_calls_from(value: Option<&Value>) -> Result<Vec<RawToolCall>, RuntimeError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = value else {
        return Err(RuntimeError::protocol("tool_calls must be an array"));
    };
    if items.len() > MAX_NATIVE_TOOL_CALLS {
        return Err(RuntimeError::protocol(format!(
            "response contains more than {MAX_NATIVE_TOOL_CALLS} tool calls"
        )));
    }
    items.iter().map(one_tool_call).collect()
}

fn one_tool_call(value: &Value) -> Result<RawToolCall, RuntimeError> {
    let Some(call) = value.as_object() else {
        return Err(RuntimeError::protocol("tool call must be an object"));
    };
    let Some(function) = call.get("function").and_then(Value::as_object) else {
        return Err(RuntimeError::protocol("tool call is missing function"));
    };
    let Some(name) = function.get("name").and_then(Value::as_str) else {
        return Err(RuntimeError::protocol(
            "tool call is missing a function name",
        ));
    };
    if name.is_empty() {
        return Err(RuntimeError::protocol("tool call function name is empty"));
    }
    let arguments = match function.get("arguments") {
        None => Value::Object(Map::new()),
        Some(Value::Object(arguments)) => Value::Object(arguments.clone()),
        Some(_) => {
            return Err(RuntimeError::protocol(
                "tool call arguments must be a JSON object",
            ));
        }
    };
    Ok(RawToolCall::new(name, arguments))
}

fn options_of(request: &GenerationRequest) -> Option<ChatOptions> {
    let sampling = request.sampling();
    let options = ChatOptions {
        temperature: sampling.temperature,
        top_p: sampling.top_p,
        top_k: sampling.top_k,
        seed: sampling.seed,
        repeat_penalty: sampling.repeat_penalty,
        num_predict: request.max_tokens(),
        num_ctx: request.context_tokens(),
    };
    let empty = options.temperature.is_none()
        && options.top_p.is_none()
        && options.top_k.is_none()
        && options.seed.is_none()
        && options.repeat_penalty.is_none()
        && options.num_predict.is_none()
        && options.num_ctx.is_none();
    if empty { None } else { Some(options) }
}

fn parse_chunk(bytes: &[u8]) -> Result<ChatChunk, RuntimeError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(RuntimeError::protocol("response body was empty"));
    }
    serde_json::from_slice(bytes).map_err(|_| RuntimeError::protocol("response was not valid JSON"))
}

fn content_of(chunk: &ChatChunk) -> String {
    chunk
        .message
        .as_ref()
        .and_then(|message| message.content.clone())
        .unwrap_or_default()
}

fn metadata_from(chunk: &ChatChunk, fallback_model: &str) -> GenerationMetadata {
    let model = chunk
        .model
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback_model);
    GenerationMetadata::new(
        model,
        finish_reason(chunk.done_reason.as_deref()),
        TokenUsage::from_counts(chunk.prompt_eval_count, chunk.eval_count),
        TimingMetadata::from_parts(
            chunk.total_duration.map(Duration::from_nanos),
            chunk.load_duration.map(Duration::from_nanos),
            chunk.prompt_eval_duration.map(Duration::from_nanos),
            chunk.eval_duration.map(Duration::from_nanos),
        ),
    )
}

fn finish_reason(value: Option<&str>) -> Option<FinishReason> {
    match value {
        Some("stop") => Some(FinishReason::Stop),
        Some("length") => Some(FinishReason::Length),
        Some(other) if !other.is_empty() => Some(FinishReason::Other(other.to_owned())),
        _ => None,
    }
}

fn error_from_backend_message(message: &str, model: &str, status: Option<u16>) -> RuntimeError {
    let clean = sanitize_message(message);
    if clean.to_ascii_lowercase().contains("not found") {
        return RuntimeError::model_not_found(model, non_empty(clean));
    }
    if matches!(status, Some(400) | Some(422)) {
        let text = if clean.is_empty() {
            match status {
                Some(code) => format!("HTTP {code}"),
                None => "bad request".to_owned(),
            }
        } else {
            clean
        };
        return RuntimeError::invalid(text);
    }
    let text = if clean.is_empty() {
        "backend failed".to_owned()
    } else {
        clean
    };
    RuntimeError::backend(status, text)
}

fn json_error_field(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let text = value.get("error")?.as_str()?;
    non_empty(sanitize_message(text))
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

fn sanitize_message(value: &str) -> String {
    let out: String = value
        .chars()
        .take(MAX_ERROR_CHARS)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    out.trim().to_owned()
}

fn map_show(model: &str, show: ShowResponse) -> ModelCapabilities {
    let mut parts = CapabilityParts {
        family: show
            .details
            .as_ref()
            .and_then(|details| details.family.clone()),
        parameter_size: show
            .details
            .as_ref()
            .and_then(|details| details.parameter_size.clone()),
        quantization: show
            .details
            .as_ref()
            .and_then(|details| details.quantization_level.clone()),
        context_length: show.model_info.as_ref().and_then(context_length_of),
        ..CapabilityParts::default()
    };

    if let Some(capabilities) = show.capabilities {
        let names: Vec<String> = capabilities
            .iter()
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty())
            .collect();
        parts.chat = if names.iter().any(|name| is_chat(name)) {
            CapabilityStatus::Confirmed
        } else {
            CapabilityStatus::NotReported
        };
        parts.tools = if names.iter().any(|name| name.eq_ignore_ascii_case("tools")) {
            CapabilityStatus::Confirmed
        } else {
            CapabilityStatus::NotReported
        };
        parts.json_mode = if names.iter().any(|name| is_json_mode(name)) {
            CapabilityStatus::Confirmed
        } else {
            CapabilityStatus::Unknown
        };
        parts.unrecognized = names
            .into_iter()
            .filter(|name| {
                !is_chat(name) && !name.eq_ignore_ascii_case("tools") && !is_json_mode(name)
            })
            .collect();
    }

    ModelCapabilities::from_parts(model, parts)
}

fn is_chat(name: &str) -> bool {
    name.eq_ignore_ascii_case("completion") || name.eq_ignore_ascii_case("chat")
}

fn is_json_mode(name: &str) -> bool {
    name.eq_ignore_ascii_case("json") || name.eq_ignore_ascii_case("json_mode")
}

fn context_length_of(info: &Map<String, Value>) -> Option<u64> {
    let mut keys: Vec<&String> = info
        .keys()
        .filter(|key| {
            let lower = key.to_ascii_lowercase();
            lower == "context_length" || lower.ends_with(".context_length")
        })
        .collect();
    keys.sort();
    for key in keys {
        if let Some(value) = info.get(key).and_then(Value::as_u64)
            && value > 0
        {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use lca_model_runtime::{GenerationOptions, Message, MessageRole, SamplingParams};

    fn request() -> GenerationRequest {
        GenerationRequest::try_new(
            "lca-agent",
            vec![
                Message::user("explain ownership"),
                Message::assistant("one owner"),
            ],
            GenerationOptions {
                system: Some("be concise".to_owned()),
                sampling: SamplingParams {
                    temperature: Some(0.2),
                    top_p: Some(0.9),
                    top_k: Some(40),
                    seed: Some(7),
                    repeat_penalty: Some(1.1),
                },
                max_tokens: Some(128),
                context_tokens: Some(4096),
                timeout: Some(Duration::from_secs(30)),
                ..GenerationOptions::default()
            },
        )
        .expect("request")
    }

    #[test]
    fn chat_payload_maps_roles_sampling_and_stream_flag() {
        let payload = chat_payload(&request(), true).expect("payload");
        assert_eq!(payload["model"], "lca-agent");
        assert_eq!(payload["stream"], true);
        assert!(payload.get("tools").is_none());
        let messages = payload["messages"].as_array().expect("messages");
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "be concise");
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[2]["role"], MessageRole::Assistant.as_str());
        let temperature = payload["options"]["temperature"]
            .as_f64()
            .expect("temperature");
        let top_p = payload["options"]["top_p"].as_f64().expect("top_p");
        let repeat_penalty = payload["options"]["repeat_penalty"]
            .as_f64()
            .expect("repeat_penalty");
        assert!((temperature - 0.2).abs() < 0.000_001);
        assert!((top_p - 0.9).abs() < 0.000_001);
        assert!((repeat_penalty - 1.1).abs() < 0.000_001);
        assert_eq!(payload["options"]["top_k"], 40);
        assert_eq!(payload["options"]["seed"], 7);
        assert_eq!(payload["options"]["num_predict"], 128);
        assert_eq!(payload["options"]["num_ctx"], 4096);

        let bare = GenerationRequest::try_new(
            "lca-agent",
            vec![Message::user("hi")],
            GenerationOptions::default(),
        )
        .expect("bare");
        let payload = chat_payload(&bare, false).expect("payload");
        assert_eq!(payload["stream"], false);
        assert!(payload.get("options").is_none());
    }

    #[test]
    fn response_mapping_preserves_absence_and_reported_metadata() {
        let sparse = response_from_chat_json(
            br#"{"model":"lca-agent","message":{"role":"assistant","content":"hello"},"done":true}"#,
            "fallback",
        )
        .expect("sparse");
        assert_eq!(sparse.text(), "hello");
        assert_eq!(sparse.model(), "lca-agent");
        assert_eq!(sparse.finish_reason(), None);
        assert_eq!(sparse.usage(), None);
        assert_eq!(sparse.timing(), None);

        let rich = response_from_chat_json(
            br#"{"model":"lca-agent","message":{"role":"assistant","content":"hello"},"done":true,"done_reason":"length","prompt_eval_count":3,"eval_count":1,"total_duration":1000000,"eval_duration":2000}"#,
            "fallback",
        )
        .expect("rich");
        assert_eq!(rich.finish_reason(), Some(&FinishReason::Length));
        let usage = rich.usage().expect("usage");
        assert_eq!(usage.input_tokens, Some(3));
        assert_eq!(usage.output_tokens, Some(1));
        let timing = rich.timing().expect("timing");
        assert_eq!(timing.total, Some(Duration::from_nanos(1_000_000)));
        assert_eq!(timing.generation, Some(Duration::from_nanos(2_000)));
        assert_eq!(timing.load, None);
        assert_eq!(timing.prompt_eval, None);
    }

    #[test]
    fn incomplete_empty_and_invalid_payloads_are_protocol_errors() {
        let incomplete = response_from_chat_json(
            br#"{"message":{"content":"partial"},"done":false}"#,
            "model",
        )
        .expect_err("done");
        assert_eq!(incomplete.kind(), "protocol_violation");

        let empty = response_from_chat_json(b"  ", "model").expect_err("empty");
        assert_eq!(empty.kind(), "protocol_violation");
        assert!(!empty.to_string().contains('{'));

        let broken = response_from_chat_json(b"{", "model").expect_err("json");
        assert_eq!(broken.kind(), "protocol_violation");
        assert!(!broken.to_string().contains('{'));
    }

    #[test]
    fn stream_frames_emit_deltas_and_one_completion() {
        let deltas = interpret_line(
            r#"{"model":"lca-agent","message":{"role":"assistant","content":"Hel"},"done":false}"#,
            "fallback",
        )
        .expect("delta");
        assert_eq!(deltas, vec![GenerationEvent::TextDelta("Hel".to_owned())]);

        let done = interpret_line(
            r#"{"message":{"content":""},"done":true,"done_reason":"stop"}"#,
            "fallback",
        )
        .expect("done");
        match &done[..] {
            [GenerationEvent::Completed(metadata)] => {
                assert_eq!(metadata.model(), "fallback");
                assert_eq!(metadata.finish_reason(), Some(&FinishReason::Stop));
                assert_eq!(metadata.usage(), None);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn other_finish_reasons_are_preserved() {
        let response = response_from_chat_json(
            br#"{"model":"m","message":{"content":"x"},"done":true,"done_reason":"unload"}"#,
            "m",
        )
        .expect("other");
        assert_eq!(
            response.finish_reason(),
            Some(&FinishReason::Other("unload".to_owned()))
        );
    }

    #[test]
    fn http_errors_do_not_copy_raw_bodies() {
        let secret = error_from_http(
            500,
            b"super-secret-password",
            "lca-agent",
            Duration::from_secs(5),
        );
        assert_eq!(secret.kind(), "backend_failure");
        assert!(!secret.to_string().contains("super-secret-password"));
        assert!(secret.to_string().contains("HTTP 500"), "{secret}");

        let explained = error_from_http(
            500,
            br#"{"error":"backend exploded"}"#,
            "lca-agent",
            Duration::from_secs(5),
        );
        assert!(
            explained.to_string().contains("backend exploded"),
            "{explained}"
        );

        let missing = error_from_http(
            404,
            br#"{"error":"model 'lca-agent' not found"}"#,
            "lca-agent",
            Duration::from_secs(5),
        );
        assert_eq!(missing.kind(), "model_not_found");

        let bad = error_from_http(
            400,
            br#"{"error":"bad options"}"#,
            "lca-agent",
            Duration::from_secs(1),
        );
        assert_eq!(bad.kind(), "invalid_request");
        assert!(bad.to_string().contains("bad options"), "{bad}");

        let timed = error_from_http(408, b"secret-body", "lca-agent", Duration::from_secs(2));
        assert_eq!(timed.kind(), "timeout");
        assert!(!timed.to_string().contains("secret-body"));

        let huge = format!("{{\"error\":\"{}\"}}", "a".repeat(800));
        let truncated = error_from_http(500, huge.as_bytes(), "lca-agent", Duration::from_secs(1));
        assert!(!truncated.to_string().contains(&"a".repeat(600)));
        assert!(truncated.to_string().contains('a'));
    }

    #[test]
    fn capability_mapping_does_not_invent_tools_or_json_mode() {
        let listed = capabilities_from_show(
            "lca-agent",
            br#"{"capabilities":["completion","vision"],"details":{"family":"qwen","parameter_size":"30B","quantization_level":"Q4_K_M"},"model_info":{"qwen2.context_length":32768,"qwen2.embedding_length":4096}}"#,
        )
        .expect("show");
        assert_eq!(listed.chat(), CapabilityStatus::Confirmed);
        assert_eq!(listed.tools(), CapabilityStatus::NotReported);
        assert_eq!(listed.json_mode(), CapabilityStatus::Unknown);
        assert_eq!(listed.context_length(), Some(32_768));
        assert_eq!(listed.family(), Some("qwen"));
        assert_eq!(listed.parameter_size(), Some("30B"));
        assert_eq!(listed.quantization(), Some("Q4_K_M"));
        assert_eq!(listed.unrecognized(), &["vision".to_owned()]);

        let silent = capabilities_from_show("lca-agent", br#"{"details":{"family":"qwen"}}"#)
            .expect("silent");
        assert_eq!(silent.chat(), CapabilityStatus::Unknown);
        assert_eq!(silent.tools(), CapabilityStatus::Unknown);
        assert_eq!(silent.json_mode(), CapabilityStatus::Unknown);
        assert_eq!(silent.context_length(), None);

        let explicit = capabilities_from_show("lca-agent", br#"{"capabilities":["tools","json"]}"#)
            .expect("explicit");
        assert_eq!(explicit.tools(), CapabilityStatus::Confirmed);
        assert_eq!(explicit.json_mode(), CapabilityStatus::Confirmed);
        assert_eq!(explicit.chat(), CapabilityStatus::NotReported);
    }

    #[test]
    fn chat_payload_advertises_tools_and_json_format_only_when_requested() {
        use lca_model_runtime::{ResponseFormat, ToolDefinition};
        use serde_json::json;

        let tool = ToolDefinition::try_new(
            "diagnostic_echo",
            "Return the provided message.",
            json!({"type": "object"}),
        )
        .expect("tool");
        let request = GenerationRequest::try_new(
            "lca-agent",
            vec![Message::user("call the tool")],
            GenerationOptions {
                tools: vec![tool],
                response_format: ResponseFormat::Json,
                ..GenerationOptions::default()
            },
        )
        .expect("request");
        let payload = chat_payload(&request, false).expect("payload");
        assert_eq!(payload["stream"], false);
        assert_eq!(payload["format"], "json");
        let tools = payload["tools"].as_array().expect("tools");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["type"], "function");
        assert_eq!(tools[0]["function"]["name"], "diagnostic_echo");
        assert_eq!(tools[0]["function"]["parameters"]["type"], "object");
        assert!(payload["messages"][0].get("tool_calls").is_none());
    }

    #[test]
    fn native_tool_calls_keep_order_and_json_arguments() {
        let response = response_from_chat_json(
            br#"{"model":"lca-agent","message":{"role":"assistant","content":"","tool_calls":[{"id":"model-supplied","function":{"name":"diagnostic_echo","arguments":{"message":"one"}}},{"function":{"name":"diagnostic_echo","arguments":{"message":"two"}}}]},"done":true,"done_reason":"stop"}"#,
            "fallback",
        )
        .expect("calls");
        assert_eq!(response.text(), "");
        let calls = response.tool_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].name(), "diagnostic_echo");
        assert_eq!(calls[0].arguments()["message"], "one");
        assert_eq!(calls[1].arguments()["message"], "two");
        assert!(!format!("{calls:?}").contains("model-supplied"));
    }

    #[test]
    fn empty_tool_calls_and_text_markers_are_not_actions() {
        let empty = response_from_chat_json(
            br#"{"model":"m","message":{"role":"assistant","content":"hello","tool_calls":[]},"done":true}"#,
            "m",
        )
        .expect("empty");
        assert!(empty.tool_calls().is_empty());
        assert_eq!(empty.text(), "hello");

        let marker = response_from_chat_json(
            br#"{"model":"m","message":{"role":"assistant","content":"use <tool_call>diagnostic_echo</tool_call> and <function=diagnostic_echo>"},"done":true}"#,
            "m",
        )
        .expect("marker");
        assert!(marker.tool_calls().is_empty());
        assert!(marker.text().contains("<tool_call>"));
        assert!(marker.text().contains("<function=diagnostic_echo>"));

        let missing_arguments = response_from_chat_json(
            br#"{"model":"m","message":{"content":"","tool_calls":[{"function":{"name":"diagnostic_echo"}}]},"done":true}"#,
            "m",
        )
        .expect("missing arguments");
        assert_eq!(
            missing_arguments.tool_calls()[0].arguments(),
            &serde_json::json!({})
        );
    }

    #[test]
    fn malformed_native_tool_calls_are_protocol_errors() {
        let cases = [
            br#"{"model":"m","message":{"content":"","tool_calls":"diagnostic_echo"},"done":true}"#.as_slice(),
            br#"{"model":"m","message":{"content":"","tool_calls":[{"function":{"name":"diagnostic_echo","arguments":"{\"message\":\"hello\"}"}}]},"done":true}"#,
            br#"{"model":"m","message":{"content":"","tool_calls":[{"name":"diagnostic_echo"}]},"done":true}"#,
            br#"{"model":"m","message":{"content":"","tool_calls":[{"function":{"name":""}}]},"done":true}"#,
            br#"{"model":"m","message":{"content":"","tool_calls":[{},{},{},{},{},{},{},{},{}]},"done":true}"#,
        ];
        for case in cases {
            let error = response_from_chat_json(case, "m").expect_err("malformed");
            assert_eq!(error.kind(), "protocol_violation", "{error}");
            assert!(!error.to_string().contains("hello"), "{error}");
            assert!(!error.to_string().contains('{'), "{error}");
        }
    }

    #[test]
    fn observed_ollama_0_40_tool_call_shape_is_preserved() {
        // Captured from Ollama 0.40.16 with qwen3:8b, stream false.
        // The model id and function index are not copied into the runtime call.
        let response = response_from_chat_json(
            br#"{"model":"qwen3:8b","message":{"role":"assistant","content":"","tool_calls":[{"id":"call_yqfuarki","function":{"index":0,"name":"diagnostic_echo","arguments":{"message":"hello"}}}]},"done":true,"done_reason":"stop"}"#,
            "fallback",
        )
        .expect("observed");
        assert_eq!(response.tool_calls().len(), 1);
        assert_eq!(response.tool_calls()[0].name(), "diagnostic_echo");
        assert_eq!(response.tool_calls()[0].arguments()["message"], "hello");
        assert!(!format!("{:?}", response.tool_calls()).contains("call_yqfuarki"));
    }

    #[test]
    fn stream_frames_do_not_interpret_tool_calls() {
        let events = interpret_line(
            r#"{"message":{"content":"Hello","tool_calls":"not-a-call"},"done":false}"#,
            "fallback",
        )
        .expect("text frame");
        assert_eq!(events, vec![GenerationEvent::TextDelta("Hello".to_owned())]);

        let marked = interpret_line(
            r#"{"message":{"content":"<tool_call>diagnostic_echo</tool_call>"},"done":true,"done_reason":"stop"}"#,
            "fallback",
        )
        .expect("marker frame");
        assert!(matches!(
            &marked[..],
            [
                GenerationEvent::TextDelta(text),
                GenerationEvent::Completed(_)
            ] if text.contains("<tool_call>")
        ));

        // Ollama 0.40.16 with qwen3:8b put a complete tool call on a non-terminal frame.
        // The stream decoder does not turn that frame into an action.
        let native = interpret_line(
            r#"{"message":{"role":"assistant","content":"","tool_calls":[{"id":"call_6205uk6a","function":{"index":0,"name":"diagnostic_echo","arguments":{"message":"hello"}}}]},"done":false}"#,
            "fallback",
        )
        .expect("native stream frame");
        assert!(native.is_empty(), "{native:?}");
    }
}
