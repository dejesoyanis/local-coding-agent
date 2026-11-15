//! This file is its own test process so the tracing callsites are first registered
//! while the recording subscriber is installed. Unit tests that load configuration
//! in parallel would otherwise cache those callsites as disabled.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use lca_config::{DEFAULT_OLLAMA_MODEL, load_from_path};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Metadata, Subscriber};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("lca-config-logs-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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
        visitor.0.push_str(event.metadata().name());
        visitor.0.push(' ');
        event.record(&mut visitor);
        self.lines.lock().expect("log lines").push(visitor.0);
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

fn capture_logs(action: impl FnOnce()) -> String {
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let subscriber = RecordingSubscriber {
        lines: Arc::clone(&lines),
    };
    tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        action();
    });
    lines.lock().expect("log lines").join("\n")
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[test]
fn logs_omit_file_comments_and_embedded_credentials() {
    let root = TempDir::new();
    let workspace = root.0.join("ws");
    std::fs::create_dir(&workspace).expect("workspace");
    let config = root.0.join("lca.toml");
    std::fs::write(
        &config,
        format!(
            "# do-not-log-this-token\nworkspace_root = '{}'\n",
            toml_path(&workspace)
        ),
    )
    .expect("write");

    let success_logs = capture_logs(|| {
        load_from_path(&config).expect("load");
    });
    assert!(
        success_logs.contains("configuration loaded"),
        "{success_logs}"
    );
    assert!(
        success_logs.contains(DEFAULT_OLLAMA_MODEL),
        "{success_logs}"
    );
    assert!(
        !success_logs.contains("do-not-log-this-token"),
        "{success_logs}"
    );

    std::fs::write(
        &config,
        format!(
            "workspace_root = '{}'\n[ollama]\nendpoint = 'http://user:super-secret-password@127.0.0.1:11434'\n",
            toml_path(&workspace)
        ),
    )
    .expect("rewrite");
    let secret_logs = capture_logs(|| {
        let error = load_from_path(&config).expect_err("credentials");
        assert_eq!(error.kind(), "endpoint_credentials");
        assert!(!error.to_string().contains("super-secret-password"));
    });
    assert!(
        secret_logs.contains("endpoint_credentials"),
        "{secret_logs}"
    );
    assert!(
        !secret_logs.contains("super-secret-password"),
        "{secret_logs}"
    );
    assert!(
        !secret_logs.contains("do-not-log-this-token"),
        "{secret_logs}"
    );
}
