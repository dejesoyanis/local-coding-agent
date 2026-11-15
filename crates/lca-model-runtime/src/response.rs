use std::time::Duration;

/// Why the backend stopped generating.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinishReason {
    /// The backend stopped on its normal end-of-turn condition.
    Stop,
    /// The backend stopped because the token limit was reached.
    Length,
    /// A backend-specific reason that this crate does not interpret.
    Other(String),
}

/// Token counts reported by the backend.
///
/// A missing count stays `None`. It is not replaced with zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenUsage {
    /// Prompt or input tokens, when the backend reported them.
    pub input_tokens: Option<u64>,
    /// Generated tokens, when the backend reported them.
    pub output_tokens: Option<u64>,
}

impl TokenUsage {
    /// Returns `None` when the backend reported neither count.
    #[must_use]
    pub const fn from_counts(
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
    ) -> Option<Self> {
        if input_tokens.is_none() && output_tokens.is_none() {
            None
        } else {
            Some(Self {
                input_tokens,
                output_tokens,
            })
        }
    }
}

/// Durations reported by the backend.
///
/// A missing duration stays `None`. It is not replaced with zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingMetadata {
    /// End-to-end duration reported by the backend.
    pub total: Option<Duration>,
    /// Model load duration, when the backend reported it.
    pub load: Option<Duration>,
    /// Prompt evaluation duration, when the backend reported it.
    pub prompt_eval: Option<Duration>,
    /// Token generation duration, when the backend reported it.
    pub generation: Option<Duration>,
}

impl TimingMetadata {
    /// Returns `None` when the backend reported no durations.
    #[must_use]
    pub const fn from_parts(
        total: Option<Duration>,
        load: Option<Duration>,
        prompt_eval: Option<Duration>,
        generation: Option<Duration>,
    ) -> Option<Self> {
        if total.is_none() && load.is_none() && prompt_eval.is_none() && generation.is_none() {
            None
        } else {
            Some(Self {
                total,
                load,
                prompt_eval,
                generation,
            })
        }
    }
}

/// Completed non-streaming generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationResponse {
    model: String,
    text: String,
    finish_reason: Option<FinishReason>,
    usage: Option<TokenUsage>,
    timing: Option<TimingMetadata>,
}

impl GenerationResponse {
    /// Builds a response from values the backend actually returned.
    ///
    /// `finish_reason`, `usage`, and `timing` stay empty when the backend omitted them.
    #[must_use]
    pub fn complete(
        model: impl Into<String>,
        text: impl Into<String>,
        finish_reason: Option<FinishReason>,
        usage: Option<TokenUsage>,
        timing: Option<TimingMetadata>,
    ) -> Self {
        Self {
            model: model.into(),
            text: text.into(),
            finish_reason,
            usage,
            timing,
        }
    }

    /// Model identifier reported for this response, or the requested model when the backend omitted it.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Generated text. This can be empty when the backend completed without emitting text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Finish reason, when the backend reported one.
    #[must_use]
    pub fn finish_reason(&self) -> Option<&FinishReason> {
        self.finish_reason.as_ref()
    }

    /// Token counts, when the backend reported any.
    #[must_use]
    pub const fn usage(&self) -> Option<TokenUsage> {
        self.usage
    }

    /// Timing, when the backend reported any duration.
    #[must_use]
    pub const fn timing(&self) -> Option<TimingMetadata> {
        self.timing
    }
}

/// Terminal metadata for a successful stream.
///
/// A successful stream emits exactly one [`GenerationEvent::Completed`] and emits it last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationMetadata {
    model: String,
    finish_reason: Option<FinishReason>,
    usage: Option<TokenUsage>,
    timing: Option<TimingMetadata>,
}

impl GenerationMetadata {
    /// Metadata taken from a terminal backend frame.
    #[must_use]
    pub fn new(
        model: impl Into<String>,
        finish_reason: Option<FinishReason>,
        usage: Option<TokenUsage>,
        timing: Option<TimingMetadata>,
    ) -> Self {
        Self {
            model: model.into(),
            finish_reason,
            usage,
            timing,
        }
    }

    /// Model identifier.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Finish reason, when the backend reported one.
    #[must_use]
    pub fn finish_reason(&self) -> Option<&FinishReason> {
        self.finish_reason.as_ref()
    }

    /// Token counts, when the backend reported any.
    #[must_use]
    pub const fn usage(&self) -> Option<TokenUsage> {
        self.usage
    }

    /// Timing, when the backend reported any duration.
    #[must_use]
    pub const fn timing(&self) -> Option<TimingMetadata> {
        self.timing
    }
}

/// One item in a generation stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerationEvent {
    /// Incremental text. Empty deltas are not emitted.
    TextDelta(String),
    /// The single successful terminal event.
    Completed(GenerationMetadata),
}

/// Returns whether `events` is zero or more text deltas followed by one completion.
#[cfg(any(test, feature = "contract"))]
#[must_use]
pub fn successful_stream_shape(events: &[GenerationEvent]) -> bool {
    let Some(GenerationEvent::Completed(_)) = events.last() else {
        return false;
    };
    let completions = events
        .iter()
        .filter(|event| matches!(event, GenerationEvent::Completed(_)))
        .count();
    completions == 1
        && events
            .iter()
            .rev()
            .skip(1)
            .all(|event| matches!(event, GenerationEvent::TextDelta(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_counts_and_durations_stay_absent() {
        assert_eq!(TokenUsage::from_counts(None, None), None);
        assert_eq!(TimingMetadata::from_parts(None, None, None, None), None);

        let usage = TokenUsage::from_counts(Some(3), None).expect("usage");
        assert_eq!(usage.input_tokens, Some(3));
        assert_eq!(usage.output_tokens, None);

        let timing = TimingMetadata::from_parts(None, None, None, Some(Duration::from_millis(2)))
            .expect("timing");
        assert_eq!(timing.generation, Some(Duration::from_millis(2)));
        assert_eq!(timing.total, None);
    }

    #[test]
    fn response_does_not_invent_optional_metadata() {
        let response = GenerationResponse::complete("model", "hello", None, None, None);
        assert_eq!(response.model(), "model");
        assert_eq!(response.text(), "hello");
        assert_eq!(response.finish_reason(), None);
        assert_eq!(response.usage(), None);
        assert_eq!(response.timing(), None);
    }

    #[test]
    fn successful_streams_end_with_one_completion() {
        let done = GenerationEvent::Completed(GenerationMetadata::new(
            "model",
            Some(FinishReason::Stop),
            None,
            None,
        ));
        assert!(successful_stream_shape(&[
            GenerationEvent::TextDelta("a".to_owned()),
            GenerationEvent::TextDelta("b".to_owned()),
            done.clone(),
        ]));
        assert!(successful_stream_shape(std::slice::from_ref(&done)));
        assert!(!successful_stream_shape(&[GenerationEvent::TextDelta(
            "a".to_owned()
        )]));
        assert!(!successful_stream_shape(&[done.clone(), done]));
    }
}
