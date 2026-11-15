//! `lca ask` streams one local generation to stdout.
//!
//! The answer is written as the model produced it. It is not parsed, saved, or executed.
//! Diagnostics go to stderr. Dropping the generation stream on cancellation closes the request.

use std::future::Future;
use std::io::Write;
use std::pin::pin;

use futures_util::FutureExt;
use futures_util::StreamExt;
use lca_config::{AgentConfig, load_from_path};
use lca_model_runtime::{
    GenerationOptions, GenerationRequest, Message, ModelRuntime, RuntimeError, report,
};
use lca_ollama::{OllamaModelRuntime, OllamaRuntimeConfig};

use crate::AskCommand;

const INTERRUPTED_EXIT: u8 = 130;

/// Loads configuration, calls the local runtime, and streams the answer.
pub async fn run_ask<W, E, C>(command: &AskCommand, stdout: &mut W, stderr: &mut E, cancel: C) -> u8
where
    W: Write,
    E: Write,
    C: Future<Output = ()>,
{
    let config = match load_from_path(&command.config) {
        Ok(config) => config,
        Err(error) => return fail(stderr, &error.to_string()),
    };
    let prompt = command.prompt.trim();
    if prompt.is_empty() {
        return fail(stderr, "prompt must not be empty");
    }
    let model = match command.model.as_deref() {
        Some(model) => model,
        None => config.model(),
    };
    let runtime = match connect(&config) {
        Ok(runtime) => runtime,
        Err(error) => return fail(stderr, &report(&error)),
    };
    let request = match GenerationRequest::try_new(
        model,
        vec![Message::user(prompt)],
        GenerationOptions {
            max_tokens: Some(config.generation_limit()),
            timeout: Some(config.request_timeout()),
            context_tokens: Some(config.context_window()),
            ..GenerationOptions::default()
        },
    ) {
        Ok(request) => request,
        Err(error) => return fail(stderr, &report(&error)),
    };
    stream_answer(&runtime, request, stdout, stderr, cancel).await
}

fn connect(config: &AgentConfig) -> Result<OllamaModelRuntime, RuntimeError> {
    OllamaModelRuntime::connect(OllamaRuntimeConfig::new(
        config.endpoint(),
        config.connect_timeout(),
        config.request_timeout(),
    ))
}

async fn stream_answer<W, E, C>(
    runtime: &dyn ModelRuntime,
    request: GenerationRequest,
    stdout: &mut W,
    stderr: &mut E,
    cancel: C,
) -> u8
where
    W: Write,
    E: Write,
    C: Future<Output = ()>,
{
    let mut cancel = pin!(cancel.fuse());
    let started = tokio::select! {
        biased;
        () = cancel.as_mut() => return interrupted(stderr),
        result = runtime.generate_stream(request) => result,
    };
    let mut stream = match started {
        Ok(stream) => stream,
        Err(error) => return fail(stderr, &report(&error)),
    };

    let mut wrote = false;
    let mut ended_with_newline = false;
    loop {
        let item = tokio::select! {
            biased;
            () = cancel.as_mut() => {
                drop(stream);
                return interrupted(stderr);
            }
            item = stream.next() => item,
        };
        match item {
            Some(Ok(lca_model_runtime::GenerationEvent::TextDelta(text))) => {
                if write_all(stdout, text.as_bytes()).is_err() {
                    return fail(stderr, "failed to write the answer");
                }
                wrote = true;
                ended_with_newline = text.ends_with('\n');
            }
            Some(Ok(lca_model_runtime::GenerationEvent::Completed(_))) => {
                if wrote && !ended_with_newline && write_all(stdout, b"\n").is_err() {
                    return fail(stderr, "failed to write the answer");
                }
                return 0;
            }
            Some(Err(error)) => return fail(stderr, &report(&error)),
            None => {
                return fail(
                    stderr,
                    "generation stream ended before a terminal completion",
                );
            }
        }
    }
}

fn write_all(stdout: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    stdout.write_all(bytes)?;
    stdout.flush()
}

fn fail(stderr: &mut impl Write, message: &str) -> u8 {
    let _ = writeln!(stderr, "lca: {message}");
    1
}

fn interrupted(stderr: &mut impl Write) -> u8 {
    let _ = writeln!(stderr, "lca: interrupted");
    INTERRUPTED_EXIT
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use async_trait::async_trait;
    use futures_util::StreamExt;
    use lca_model_runtime::{
        GenerationEvent, GenerationMetadata, GenerationResponse, GenerationStream,
        ModelCapabilities, ModelRuntime, RuntimeError,
    };
    use std::time::Instant;

    struct Recording {
        bytes: Vec<u8>,
        flushes: usize,
        on_write: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl Write for Recording {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            if let Some(sender) = self.on_write.take() {
                let _ = sender.send(());
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    fn request() -> GenerationRequest {
        GenerationRequest::try_new(
            "model",
            vec![Message::user("ping")],
            GenerationOptions::default(),
        )
        .expect("request")
    }

    struct Scripted {
        events: Vec<GenerationEvent>,
        hang_after: bool,
        delay: Duration,
    }

    #[async_trait]
    impl ModelRuntime for Scripted {
        async fn generate(
            &self,
            request: GenerationRequest,
        ) -> Result<GenerationResponse, RuntimeError> {
            request.validate()?;
            Ok(GenerationResponse::complete(
                request.model(),
                "",
                None,
                None,
                None,
            ))
        }

        async fn generate_stream(
            &self,
            request: GenerationRequest,
        ) -> Result<GenerationStream, RuntimeError> {
            request.validate()?;
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            let events = self.events.clone();
            let hang_after = self.hang_after;
            let stream = futures_util::stream::iter(events.into_iter().map(Ok));
            if hang_after {
                let tail = futures_util::stream::once(async {
                    std::future::pending::<Result<GenerationEvent, RuntimeError>>().await
                });
                return Ok(GenerationStream::from_stream(stream.chain(tail)));
            }
            Ok(GenerationStream::from_stream(stream))
        }

        async fn capabilities(&self, model: &str) -> Result<ModelCapabilities, RuntimeError> {
            Ok(ModelCapabilities::from_parts(
                model,
                lca_model_runtime::CapabilityParts::default(),
            ))
        }
    }

    #[tokio::test]
    async fn deltas_are_flushed_before_the_terminal_newline() {
        let runtime = Scripted {
            events: vec![
                GenerationEvent::TextDelta("Hello".to_owned()),
                GenerationEvent::TextDelta(" world".to_owned()),
                GenerationEvent::Completed(GenerationMetadata::new("model", None, None, None)),
            ],
            hang_after: false,
            delay: Duration::ZERO,
        };
        let mut stdout = Recording {
            bytes: Vec::new(),
            flushes: 0,
            on_write: None,
        };
        let mut stderr = Vec::new();
        let code = stream_answer(
            &runtime,
            request(),
            &mut stdout,
            &mut stderr,
            std::future::pending::<()>(),
        )
        .await;
        assert_eq!(code, 0);
        assert_eq!(
            String::from_utf8(stdout.bytes).expect("utf-8"),
            "Hello world\n"
        );
        assert!(stdout.flushes >= 2, "flushes {}", stdout.flushes);
        assert!(stderr.is_empty());
    }

    #[tokio::test]
    async fn cancellation_before_headers_returns_130_quickly() {
        let runtime = Scripted {
            events: vec![GenerationEvent::TextDelta("late".to_owned())],
            hang_after: false,
            delay: Duration::from_secs(30),
        };
        let started = Instant::now();
        let code = tokio::time::timeout(
            Duration::from_secs(2),
            stream_answer(
                &runtime,
                request(),
                &mut Vec::new(),
                &mut Vec::new(),
                std::future::ready(()),
            ),
        )
        .await
        .expect("cancel hung");
        assert_eq!(code, 130);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn cancellation_after_a_delta_drops_the_stream() {
        let runtime = Scripted {
            events: vec![GenerationEvent::TextDelta("Hi".to_owned())],
            hang_after: true,
            delay: Duration::ZERO,
        };
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let mut stdout = Recording {
            bytes: Vec::new(),
            flushes: 0,
            on_write: Some(sender),
        };
        let mut stderr = Vec::new();
        let started = Instant::now();
        let code = tokio::time::timeout(
            Duration::from_secs(2),
            stream_answer(&runtime, request(), &mut stdout, &mut stderr, async move {
                let _ = receiver.await;
            }),
        )
        .await
        .expect("mid-stream cancel hung");
        assert_eq!(code, 130);
        assert_eq!(String::from_utf8_lossy(&stdout.bytes), "Hi");
        let err = String::from_utf8(stderr).expect("utf-8");
        assert!(err.contains("interrupted"), "{err}");
        assert!(!err.contains("Hi"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
