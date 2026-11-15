mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use lca_model_runtime::{GenerationOptions, GenerationRequest, Message, ModelRuntime};
use lca_ollama::{OllamaModelRuntime, OllamaRuntimeConfig};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Metadata, Subscriber};

use common::{json_body, spawn};

struct RecordingSubscriber {
    lines: Arc<Mutex<Vec<String>>>,
}

struct LineVisitor(String);

impl Visit for LineVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field.name(), value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.push(field.name(), &format!("{value:?}"));
    }
}

impl LineVisitor {
    fn push(&mut self, name: &str, value: &str) {
        self.0.push_str(name);
        self.0.push('=');
        self.0.push_str(value);
        self.0.push(' ');
    }
}

impl Subscriber for RecordingSubscriber {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut visitor = LineVisitor(String::new());
        event.record(&mut visitor);
        self.lines.lock().expect("lines").push(visitor.0);
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }
}

#[tokio::test]
async fn logs_include_the_model_and_omit_the_prompt() {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let subscriber = RecordingSubscriber {
        lines: Arc::clone(&lines),
    };
    tracing::subscriber::set_global_default(subscriber).expect("subscriber");
    tracing::callsite::rebuild_interest_cache();

    let mock = spawn(|_| {
        json_body(
            200,
            r#"{"model":"lca-agent","message":{"role":"assistant","content":"ok"},"done":true,"done_reason":"stop"}"#,
        )
    })
    .await;
    let runtime = OllamaModelRuntime::connect(OllamaRuntimeConfig::new(
        mock.endpoint(),
        Duration::from_secs(1),
        Duration::from_secs(1),
    ))
    .expect("runtime");
    let request = GenerationRequest::try_new(
        "lca-agent",
        vec![Message::user("do-not-log-this-prompt")],
        GenerationOptions::default(),
    )
    .expect("request");
    runtime.generate(request).await.expect("generate");
    let recorded = lines.lock().expect("lines").join("\n");
    assert!(recorded.contains("lca-agent"), "{recorded}");
    assert!(!recorded.contains("do-not-log-this-prompt"), "{recorded}");
}
