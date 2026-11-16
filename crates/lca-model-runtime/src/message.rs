use std::fmt;

use crate::tool::RawToolCall;

/// Role of one chat message.
///
/// [`Self::Tool`] carries an executed tool result. It is data for the next turn, not a
/// system instruction. Multimodal content is not part of this contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageRole {
    /// Instructions that apply to the whole request.
    System,
    /// A user turn.
    User,
    /// A previous model turn.
    Assistant,
    /// One tool result associated with a previous assistant tool call.
    Tool,
}

impl MessageRole {
    /// Stable lowercase name used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
        }
    }
}

impl fmt::Display for MessageRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One text message.
///
/// The content is preserved as supplied. [`crate::GenerationRequest`] rejects empty content
/// unless the message is an assistant turn that carries tool calls.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    role: MessageRole,
    content: String,
    tool_name: Option<String>,
    tool_call_id: Option<String>,
    tool_calls: Vec<RawToolCall>,
}

impl Message {
    /// Message with an explicit role.
    pub fn new(role: MessageRole, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
            tool_name: None,
            tool_call_id: None,
            tool_calls: Vec::new(),
        }
    }

    /// Assistant turn that echoes structured tool calls.
    ///
    /// Content may be empty when the backend returned only calls. The calls are not executed
    /// by this crate.
    pub fn assistant_calls(content: impl Into<String>, tool_calls: Vec<RawToolCall>) -> Self {
        Self {
            role: MessageRole::Assistant,
            content: content.into(),
            tool_name: None,
            tool_call_id: None,
            tool_calls,
        }
    }

    /// Tool result bound to a tool name and, when the backend provided one, a call id.
    pub fn tool_result(
        name: impl Into<String>,
        call_id: Option<String>,
        content: impl Into<String>,
    ) -> Self {
        Self {
            role: MessageRole::Tool,
            content: content.into(),
            tool_name: Some(name.into()),
            tool_call_id: call_id,
            tool_calls: Vec::new(),
        }
    }

    /// System message.
    pub fn system(content: impl Into<String>) -> Self {
        Self::new(MessageRole::System, content)
    }

    /// User message.
    pub fn user(content: impl Into<String>) -> Self {
        Self::new(MessageRole::User, content)
    }

    /// Assistant message.
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new(MessageRole::Assistant, content)
    }

    /// Role of this message.
    #[must_use]
    pub const fn role(&self) -> MessageRole {
        self.role
    }

    /// Text content.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// Tool name on a tool-result message.
    #[must_use]
    pub fn tool_name(&self) -> Option<&str> {
        self.tool_name.as_deref()
    }

    /// Backend call id, when one was preserved.
    #[must_use]
    pub fn tool_call_id(&self) -> Option<&str> {
        self.tool_call_id.as_deref()
    }

    /// Structured calls echoed on an assistant message.
    #[must_use]
    pub fn tool_calls(&self) -> &[RawToolCall] {
        &self.tool_calls
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_have_stable_names() {
        assert_eq!(MessageRole::System.as_str(), "system");
        assert_eq!(MessageRole::User.to_string(), "user");
        assert_eq!(MessageRole::Assistant.as_str(), "assistant");
        assert_eq!(MessageRole::Tool.as_str(), "tool");
    }

    #[test]
    fn constructors_keep_role_and_text() {
        let system = Message::system("stay local");
        let user = Message::user("explain ownership");
        let assistant = Message::assistant("ownership is a set of rules");
        assert_eq!(system.role(), MessageRole::System);
        assert_eq!(system.content(), "stay local");
        assert_eq!(user.role(), MessageRole::User);
        assert_eq!(assistant.role(), MessageRole::Assistant);
        assert_eq!(
            Message::new(MessageRole::User, "hi").content(),
            Message::user("hi").content()
        );
    }

    #[test]
    fn tool_messages_keep_the_call_association() {
        let call = crate::tool::RawToolCall::new("read_file", serde_json::json!({"path": "a.rs"}))
            .with_id("call-1");
        let assistant = Message::assistant_calls("", vec![call.clone()]);
        assert_eq!(assistant.role(), MessageRole::Assistant);
        assert_eq!(assistant.tool_calls(), &[call]);
        assert!(assistant.content().is_empty());

        let result = Message::tool_result("read_file", Some("call-1".to_owned()), "{\"ok\":true}");
        assert_eq!(result.role(), MessageRole::Tool);
        assert_eq!(result.tool_name(), Some("read_file"));
        assert_eq!(result.tool_call_id(), Some("call-1"));
        assert!(result.tool_calls().is_empty());
    }
}
