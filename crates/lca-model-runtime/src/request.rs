use std::time::Duration;

use crate::error::RuntimeError;
use crate::message::{Message, MessageRole};
use crate::tool::{
    MAX_NATIVE_TOOL_CALLS, MAX_TOOLS_PER_REQUEST, ResponseFormat, ToolDefinition, valid_tool_name,
};

/// Largest accepted model identifier, in bytes.
pub const MAX_MODEL_NAME_LEN: usize = 256;

/// Largest accepted number of chat messages in one request.
pub const MAX_MESSAGES: usize = 256;

/// Largest accepted message or system instruction, in characters.
pub const MAX_MESSAGE_CHARS: usize = 1024 * 1024;

/// Largest accepted context window, in tokens.
pub const MAX_CONTEXT_TOKENS: u32 = 1_048_576;

/// Largest accepted request timeout.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(60 * 60);

const MAX_TOP_K: u32 = 10_000;

/// Optional sampling controls.
///
/// Fields left as `None` are not sent. Adapters must not invent replacements.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SamplingParams {
    /// Sampling temperature. Accepted range is `0.0..=2.0`.
    pub temperature: Option<f32>,
    /// Nucleus sampling probability. Accepted range is `0.0..=1.0`.
    pub top_p: Option<f32>,
    /// Candidate cutoff. Accepted range is `1..=10_000`.
    pub top_k: Option<u32>,
    /// Deterministic seed.
    pub seed: Option<i64>,
    /// Repetition penalty. Accepted range is `0.0..=4.0`.
    pub repeat_penalty: Option<f32>,
}

/// Optional generation settings that are not part of the message list.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GenerationOptions {
    /// Extra system instructions, sent ahead of `messages` when set.
    pub system: Option<String>,
    /// Sampling controls.
    pub sampling: SamplingParams,
    /// Upper bound on generated tokens.
    pub max_tokens: Option<u32>,
    /// Deadline for this request. `None` uses the runtime's configured deadline.
    pub timeout: Option<Duration>,
    /// Context window in tokens.
    pub context_tokens: Option<u32>,
    /// Tool definitions to advertise. Empty keeps the text-only request shape.
    pub tools: Vec<ToolDefinition>,
    /// Requested shape of the assistant text. The default is ordinary text.
    pub response_format: ResponseFormat,
}

/// Validated request for one generation.
///
/// Construction rejects empty prompts, illegal sampling values, and unbounded sizes.
/// Adapters call [`Self::validate`] again so a contract test can still present an invalid value.
#[derive(Debug, Clone, PartialEq)]
pub struct GenerationRequest {
    model: String,
    messages: Vec<Message>,
    system: Option<String>,
    sampling: SamplingParams,
    max_tokens: Option<u32>,
    timeout: Option<Duration>,
    context_tokens: Option<u32>,
    tools: Vec<ToolDefinition>,
    response_format: ResponseFormat,
}

impl GenerationRequest {
    /// Validates and stores a generation request.
    pub fn try_new(
        model: impl Into<String>,
        messages: Vec<Message>,
        options: GenerationOptions,
    ) -> Result<Self, RuntimeError> {
        let request = Self::from_parts(model.into(), messages, options);
        request.validate()?;
        Ok(request)
    }

    /// Checks the contract invariants.
    ///
    /// The error text names the field and the reason. It does not include message content.
    pub fn validate(&self) -> Result<(), RuntimeError> {
        validate_model(&self.model)?;
        if let Some(system) = &self.system {
            validate_text(system, "system instructions")?;
        }
        if self.messages.is_empty() {
            return Err(RuntimeError::invalid(
                "generation request needs at least one message",
            ));
        }
        if self.messages.len() > MAX_MESSAGES {
            return Err(RuntimeError::invalid(
                "generation request has too many messages",
            ));
        }
        for message in &self.messages {
            validate_message(message)?;
        }
        if let Some(max_tokens) = self.max_tokens
            && max_tokens == 0
        {
            return Err(RuntimeError::invalid(
                "max_tokens must be greater than zero",
            ));
        }
        if let Some(context_tokens) = self.context_tokens {
            if context_tokens == 0 || context_tokens > MAX_CONTEXT_TOKENS {
                return Err(RuntimeError::invalid(
                    "context window must be from 1 through 1048576 tokens",
                ));
            }
            if let Some(max_tokens) = self.max_tokens
                && max_tokens > context_tokens
            {
                return Err(RuntimeError::invalid(
                    "max_tokens exceeds the context window",
                ));
            }
        }
        if let Some(timeout) = self.timeout
            && (timeout.is_zero() || timeout > MAX_TIMEOUT)
        {
            return Err(RuntimeError::invalid(
                "timeout must be from 1ms through 3600s",
            ));
        }
        validate_sampling(&self.sampling)?;
        validate_tools(&self.tools)?;
        Ok(())
    }

    #[cfg(any(test, feature = "contract"))]
    pub(crate) fn contract_invalid() -> Self {
        Self::from_parts(
            String::new(),
            vec![Message::user("ping")],
            GenerationOptions::default(),
        )
    }

    /// Model identifier.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Chat messages, excluding the optional system instructions.
    #[must_use]
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// Optional system instructions.
    #[must_use]
    pub fn system(&self) -> Option<&str> {
        self.system.as_deref()
    }

    /// Sampling controls.
    #[must_use]
    pub fn sampling(&self) -> &SamplingParams {
        &self.sampling
    }

    /// Optional generation cap, in tokens.
    #[must_use]
    pub const fn max_tokens(&self) -> Option<u32> {
        self.max_tokens
    }

    /// Optional request deadline.
    #[must_use]
    pub const fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Optional context window, in tokens.
    #[must_use]
    pub const fn context_tokens(&self) -> Option<u32> {
        self.context_tokens
    }

    /// Tool definitions advertised with this request.
    #[must_use]
    pub fn tools(&self) -> &[ToolDefinition] {
        &self.tools
    }

    /// Requested assistant-text shape.
    #[must_use]
    pub const fn response_format(&self) -> ResponseFormat {
        self.response_format
    }

    fn from_parts(model: String, messages: Vec<Message>, options: GenerationOptions) -> Self {
        Self {
            model,
            messages,
            system: options.system,
            sampling: options.sampling,
            max_tokens: options.max_tokens,
            timeout: options.timeout,
            context_tokens: options.context_tokens,
            tools: options.tools,
            response_format: options.response_format,
        }
    }
}

fn validate_tools(tools: &[ToolDefinition]) -> Result<(), RuntimeError> {
    if tools.len() > MAX_TOOLS_PER_REQUEST {
        return Err(RuntimeError::invalid(
            "generation request has too many tools",
        ));
    }
    let mut names = Vec::with_capacity(tools.len());
    for tool in tools {
        tool.validate()?;
        if names
            .iter()
            .any(|existing: &String| existing == tool.name())
        {
            return Err(RuntimeError::invalid("tool names must be unique"));
        }
        names.push(tool.name().to_owned());
    }
    Ok(())
}

fn validate_model(model: &str) -> Result<(), RuntimeError> {
    if model.is_empty() {
        return Err(RuntimeError::invalid("model name must not be empty"));
    }
    if model.len() > MAX_MODEL_NAME_LEN {
        return Err(RuntimeError::invalid("model name is too long"));
    }
    if model
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(RuntimeError::invalid(
            "model name must not contain whitespace or control characters",
        ));
    }
    Ok(())
}

fn validate_message(message: &Message) -> Result<(), RuntimeError> {
    match message.role() {
        MessageRole::Assistant if !message.tool_calls().is_empty() => {
            if message.tool_calls().len() > MAX_NATIVE_TOOL_CALLS {
                return Err(RuntimeError::invalid(
                    "assistant message has too many tool calls",
                ));
            }
            if !message.content().trim().is_empty() {
                validate_text(message.content(), "message content")?;
            }
            if message.tool_name().is_some() || message.tool_call_id().is_some() {
                return Err(RuntimeError::invalid(
                    "assistant message cannot carry a tool result identity",
                ));
            }
            Ok(())
        }
        MessageRole::Tool => {
            validate_text(message.content(), "message content")?;
            match message.tool_name() {
                Some(name) if valid_tool_name(name) => {}
                _ => {
                    return Err(RuntimeError::invalid("tool message needs a tool name"));
                }
            }
            if !message.tool_calls().is_empty() {
                return Err(RuntimeError::invalid(
                    "tool message cannot carry tool calls",
                ));
            }
            Ok(())
        }
        MessageRole::System | MessageRole::User | MessageRole::Assistant => {
            if message.tool_name().is_some()
                || message.tool_call_id().is_some()
                || !message.tool_calls().is_empty()
            {
                return Err(RuntimeError::invalid(
                    "only assistant and tool messages carry tool metadata",
                ));
            }
            validate_text(message.content(), "message content")
        }
    }
}

fn validate_text(value: &str, field: &str) -> Result<(), RuntimeError> {
    if value.trim().is_empty() {
        return Err(RuntimeError::invalid(format!("{field} must not be empty")));
    }
    if value.chars().count() > MAX_MESSAGE_CHARS {
        return Err(RuntimeError::invalid(format!("{field} is too long")));
    }
    Ok(())
}

fn validate_sampling(sampling: &SamplingParams) -> Result<(), RuntimeError> {
    if let Some(temperature) = sampling.temperature
        && (!temperature.is_finite() || !(0.0..=2.0).contains(&temperature))
    {
        return Err(RuntimeError::invalid(
            "temperature must be finite and from 0 through 2",
        ));
    }
    if let Some(top_p) = sampling.top_p
        && (!top_p.is_finite() || !(0.0..=1.0).contains(&top_p))
    {
        return Err(RuntimeError::invalid(
            "top_p must be finite and from 0 through 1",
        ));
    }
    if let Some(top_k) = sampling.top_k
        && (top_k == 0 || top_k > MAX_TOP_K)
    {
        return Err(RuntimeError::invalid("top_k must be from 1 through 10000"));
    }
    if let Some(repeat_penalty) = sampling.repeat_penalty
        && (!repeat_penalty.is_finite() || !(0.0..=4.0).contains(&repeat_penalty))
    {
        return Err(RuntimeError::invalid(
            "repeat_penalty must be finite and from 0 through 4",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_request(model: &str, content: &str) -> Result<GenerationRequest, RuntimeError> {
        GenerationRequest::try_new(
            model,
            vec![Message::user(content)],
            GenerationOptions::default(),
        )
    }

    #[test]
    fn valid_request_keeps_messages_and_optional_settings() {
        let request = GenerationRequest::try_new(
            "lca-agent",
            vec![
                Message::user("explain ownership"),
                Message::assistant("values have one owner"),
                Message::user("what about borrowing?"),
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
                timeout: Some(Duration::from_secs(30)),
                context_tokens: Some(4096),
                ..GenerationOptions::default()
            },
        )
        .expect("request");

        assert_eq!(request.model(), "lca-agent");
        assert_eq!(request.messages().len(), 3);
        assert_eq!(
            request.messages()[0].role(),
            crate::message::MessageRole::User
        );
        assert_eq!(
            request.messages()[1].role(),
            crate::message::MessageRole::Assistant
        );
        assert_eq!(request.system(), Some("be concise"));
        assert_eq!(request.sampling().temperature, Some(0.2));
        assert_eq!(request.sampling().seed, Some(7));
        assert_eq!(request.max_tokens(), Some(128));
        assert_eq!(request.timeout(), Some(Duration::from_secs(30)));
        assert_eq!(request.context_tokens(), Some(4096));
        assert!(request.validate().is_ok());
    }

    #[test]
    fn validation_rejects_illegal_requests_without_echoing_text() {
        let secret = "do-not-echo-this-prompt";
        let cases = [
            user_request("", secret),
            user_request("bad name", secret),
            user_request(&"m".repeat(MAX_MODEL_NAME_LEN + 1), secret),
            user_request("model", "   "),
            GenerationRequest::try_new("model", Vec::new(), GenerationOptions::default()),
            GenerationRequest::try_new(
                "model",
                vec![Message::user("ok")],
                GenerationOptions {
                    system: Some("  ".to_owned()),
                    ..GenerationOptions::default()
                },
            ),
            GenerationRequest::try_new(
                "model",
                vec![Message::user("ok")],
                GenerationOptions {
                    max_tokens: Some(0),
                    ..GenerationOptions::default()
                },
            ),
            GenerationRequest::try_new(
                "model",
                vec![Message::user("ok")],
                GenerationOptions {
                    max_tokens: Some(8),
                    context_tokens: Some(4),
                    ..GenerationOptions::default()
                },
            ),
            GenerationRequest::try_new(
                "model",
                vec![Message::user("ok")],
                GenerationOptions {
                    timeout: Some(Duration::ZERO),
                    ..GenerationOptions::default()
                },
            ),
            GenerationRequest::try_new(
                "model",
                vec![Message::user("ok")],
                GenerationOptions {
                    sampling: SamplingParams {
                        temperature: Some(f32::NAN),
                        ..SamplingParams::default()
                    },
                    ..GenerationOptions::default()
                },
            ),
            GenerationRequest::try_new(
                "model",
                vec![Message::user("ok")],
                GenerationOptions {
                    sampling: SamplingParams {
                        top_p: Some(1.1),
                        ..SamplingParams::default()
                    },
                    ..GenerationOptions::default()
                },
            ),
            GenerationRequest::try_new(
                "model",
                vec![Message::user("ok")],
                GenerationOptions {
                    sampling: SamplingParams {
                        top_k: Some(0),
                        ..SamplingParams::default()
                    },
                    ..GenerationOptions::default()
                },
            ),
        ];

        for case in cases {
            let error = case.expect_err("invalid");
            assert_eq!(error.kind(), "invalid_request");
            assert!(!error.to_string().contains(secret), "{error}");
        }
    }

    #[test]
    fn message_and_count_limits_are_enforced() {
        let too_many = vec![Message::user("ok"); MAX_MESSAGES + 1];
        let error = GenerationRequest::try_new("model", too_many, GenerationOptions::default())
            .expect_err("count");
        assert!(error.to_string().contains("too many messages"), "{error}");

        let huge = "x".repeat(MAX_MESSAGE_CHARS + 1);
        let error = user_request("model", &huge).expect_err("length");
        assert!(error.to_string().contains("too long"), "{error}");
        assert!(!error.to_string().contains(&huge[..32]), "{error}");
    }

    #[test]
    fn boundary_sampling_values_are_accepted() {
        let request = GenerationRequest::try_new(
            "model",
            vec![Message::system("rules"), Message::user("question")],
            GenerationOptions {
                sampling: SamplingParams {
                    temperature: Some(0.0),
                    top_p: Some(1.0),
                    top_k: Some(MAX_TOP_K),
                    seed: Some(i64::MIN),
                    repeat_penalty: Some(4.0),
                },
                timeout: Some(MAX_TIMEOUT),
                context_tokens: Some(MAX_CONTEXT_TOKENS),
                max_tokens: Some(MAX_CONTEXT_TOKENS),
                ..GenerationOptions::default()
            },
        )
        .expect("boundaries");
        assert_eq!(
            request.messages()[0].role(),
            crate::message::MessageRole::System
        );
    }
}
