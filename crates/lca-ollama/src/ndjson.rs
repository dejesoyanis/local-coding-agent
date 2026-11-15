use std::collections::VecDeque;

use futures_util::stream::{self, Stream, StreamExt};
use lca_model_runtime::{GenerationEvent, RuntimeError};

use crate::map::interpret_line;

/// Largest accepted NDJSON frame, in bytes. A larger frame is a protocol violation.
pub const MAX_STREAM_FRAME_BYTES: usize = 1024 * 1024;

pub(crate) struct FrameParser {
    buffer: Vec<u8>,
    lines: VecDeque<String>,
    max_frame: usize,
}

impl FrameParser {
    pub(crate) fn new(max_frame: usize) -> Self {
        Self {
            buffer: Vec::new(),
            lines: VecDeque::new(),
            max_frame,
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        self.buffer.extend_from_slice(bytes);
        while let Some(position) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<u8> = self.buffer.drain(..=position).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            if line.len() > self.max_frame {
                self.buffer.clear();
                self.lines.clear();
                return Err(frame_too_large(self.max_frame));
            }
            let text = String::from_utf8(line)
                .map_err(|_| RuntimeError::protocol("stream frame is not utf-8"))?;
            self.lines.push_back(text);
        }
        if self.buffer.len() > self.max_frame {
            self.buffer.clear();
            return Err(frame_too_large(self.max_frame));
        }
        Ok(())
    }

    pub(crate) fn pop_line(&mut self) -> Option<String> {
        self.lines.pop_front()
    }

    pub(crate) fn has_buffered_bytes(&self) -> bool {
        self.buffer.iter().any(|byte| !byte.is_ascii_whitespace())
    }
}

fn frame_too_large(max_frame: usize) -> RuntimeError {
    RuntimeError::protocol(format!("stream frame exceeds {max_frame} bytes"))
}

struct DecodeState<S> {
    incoming: S,
    parser: FrameParser,
    pending: VecDeque<GenerationEvent>,
    failure: Option<RuntimeError>,
    fallback_model: String,
    saw_done: bool,
    finished: bool,
}

/// Turns transport chunks into generation events.
///
/// A chunk may end inside a JSON line, and one chunk may contain several lines.
/// The stream emits at most one [`GenerationEvent::Completed`]. A later poll returns `None`.
/// End of input without that completion is [`RuntimeError::StreamInterrupted`].
pub(crate) fn events_from_chunks<S>(
    incoming: S,
    fallback_model: String,
    max_frame: usize,
) -> impl Stream<Item = Result<GenerationEvent, RuntimeError>> + Send
where
    S: Stream<Item = Result<Vec<u8>, RuntimeError>> + Send + Unpin,
{
    stream::unfold(
        DecodeState {
            incoming,
            parser: FrameParser::new(max_frame),
            pending: VecDeque::new(),
            failure: None,
            fallback_model,
            saw_done: false,
            finished: false,
        },
        |mut state| async move {
            if state.finished {
                return None;
            }
            loop {
                if let Some(event) = state.pending.pop_front() {
                    if matches!(event, GenerationEvent::Completed(_)) {
                        state.saw_done = true;
                    }
                    return Some((Ok(event), state));
                }
                if let Some(error) = state.failure.take() {
                    state.finished = true;
                    return Some((Err(error), state));
                }
                if state.saw_done {
                    return None;
                }
                match state.incoming.next().await {
                    Some(Ok(bytes)) => {
                        if let Err(error) = state.parser.push(&bytes) {
                            state.finished = true;
                            return Some((Err(error), state));
                        }
                        while let Some(line) = state.parser.pop_line() {
                            match interpret_line(&line, &state.fallback_model) {
                                Ok(events) => state.pending.extend(events),
                                Err(error) => {
                                    state.failure = Some(error);
                                    break;
                                }
                            }
                        }
                    }
                    Some(Err(error)) => {
                        state.finished = true;
                        return Some((Err(error), state));
                    }
                    None => {
                        state.finished = true;
                        if state.parser.has_buffered_bytes() {
                            return Some((
                                Err(RuntimeError::protocol("stream ended inside a frame")),
                                state,
                            ));
                        }
                        if !state.saw_done {
                            return Some((Err(RuntimeError::stream_interrupted(None)), state));
                        }
                        return None;
                    }
                }
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    fn line(content: &str, done: bool) -> String {
        format!(
            "{{\"model\":\"m\",\"message\":{{\"role\":\"assistant\",\"content\":\"{content}\"}},\"done\":{done}}}"
        )
    }

    async fn collect(
        chunks: Vec<&[u8]>,
        max_frame: usize,
    ) -> Vec<Result<GenerationEvent, RuntimeError>> {
        let incoming = stream::iter(chunks.into_iter().map(|chunk| Ok(chunk.to_vec())));
        let mut decoded = std::pin::pin!(events_from_chunks(incoming, "m".to_owned(), max_frame));
        let mut events = Vec::new();
        while let Some(event) = decoded.next().await {
            let stop = event.is_err();
            events.push(event);
            if stop {
                assert!(decoded.next().await.is_none(), "error was not terminal");
                break;
            }
        }
        events
    }

    #[test]
    fn parser_splits_lines_and_keeps_a_partial_tail() {
        let mut parser = FrameParser::new(128);
        parser.push(b"{\"a\":1}\n{\"b\":").expect("first");
        assert_eq!(parser.pop_line().as_deref(), Some("{\"a\":1}"));
        assert!(parser.pop_line().is_none());
        assert!(parser.has_buffered_bytes());
        parser.push(b"2}\r\n").expect("second");
        assert_eq!(parser.pop_line().as_deref(), Some("{\"b\":2}"));
        assert!(!parser.has_buffered_bytes());
    }

    #[test]
    fn parser_rejects_an_oversized_frame() {
        let mut parser = FrameParser::new(8);
        let error = parser.push(b"0123456789").expect_err("limit");
        assert_eq!(error.kind(), "protocol_violation");
        assert!(!parser.has_buffered_bytes());
    }

    #[tokio::test]
    async fn one_chunk_can_carry_several_frames_and_a_terminal_completion() {
        let body = format!("{}\n{}\n", line("Hello", false), line(" world", true));
        let events = collect(vec![body.as_bytes()], 1024).await;
        assert_eq!(
            events,
            vec![
                Ok(GenerationEvent::TextDelta("Hello".to_owned())),
                Ok(GenerationEvent::TextDelta(" world".to_owned())),
                Ok(GenerationEvent::Completed(
                    lca_model_runtime::GenerationMetadata::new("m", None, None, None)
                )),
            ]
        );
    }

    #[tokio::test]
    async fn a_json_line_split_across_chunks_is_one_delta() {
        let full = format!("{}\n", line("Hello", true));
        let (left, right) = full.split_at(full.len() / 2);
        let events = collect(vec![left.as_bytes(), right.as_bytes()], 1024).await;
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(
            events[0].as_ref().expect("delta"),
            &GenerationEvent::TextDelta("Hello".to_owned())
        );
        assert!(matches!(events[1], Ok(GenerationEvent::Completed(_))));
    }

    #[tokio::test]
    async fn missing_terminal_frame_is_not_a_completion() {
        let body = format!("{}\n", line("partial", false));
        let events = collect(vec![body.as_bytes()], 1024).await;
        assert_eq!(
            events[0].as_ref().expect("delta"),
            &GenerationEvent::TextDelta("partial".to_owned())
        );
        let error = events[1].as_ref().expect_err("interrupted");
        assert_eq!(error.kind(), "stream_interrupted");
        assert!(
            events
                .iter()
                .all(|event| { !matches!(event, Ok(GenerationEvent::Completed(_))) })
        );
    }

    #[tokio::test]
    async fn a_partial_frame_at_end_of_input_is_a_protocol_error() {
        let events = collect(vec![br#"{"message":{"content":"Hi""#], 1024).await;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].as_ref().expect_err("partial").kind(),
            "protocol_violation"
        );
    }

    #[tokio::test]
    async fn an_invalid_frame_is_terminal() {
        let events = collect(vec![b"not-json\n"], 1024).await;
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].as_ref().expect_err("json").kind(),
            "protocol_violation"
        );
    }

    #[tokio::test]
    async fn frame_limit_applies_to_the_decoder() {
        let events = collect(vec![b"0123456789"], 8).await;
        assert_eq!(
            events[0].as_ref().expect_err("limit").kind(),
            "protocol_violation"
        );
    }
}
