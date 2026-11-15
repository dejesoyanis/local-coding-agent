use std::fmt;

/// Role of one chat message.
///
/// Tool and multimodal roles are not part of this milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageRole {
    /// Instructions that apply to the whole request.
    System,
    /// A user turn.
    User,
    /// A previous model turn.
    Assistant,
}

impl MessageRole {
    /// Stable lowercase name used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
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
/// The content is preserved as supplied. [`crate::GenerationRequest`] rejects empty content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    role: MessageRole,
    content: String,
}

impl Message {
    /// Message with an explicit role.
    pub fn new(role: MessageRole, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_have_stable_names() {
        assert_eq!(MessageRole::System.as_str(), "system");
        assert_eq!(MessageRole::User.to_string(), "user");
        assert_eq!(MessageRole::Assistant.as_str(), "assistant");
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
}
