//! Optional live tool-calling probe.
//!
//! `cargo test --workspace` skips the network call unless `LCA_OLLAMA_SMOKE` is `1`.
//! A model response with no validated action fails this test. The tool is not executed.
//!
//! ```text
//! $env:LCA_OLLAMA_SMOKE = "1"
//! cargo test -p lca-cli --test live_probe -- --nocapture
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("lca-live-probe-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("temp");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn live_tools_probe_against_local_ollama() {
    if std::env::var("LCA_OLLAMA_SMOKE").ok().as_deref() != Some("1") {
        eprintln!("skipping live tool probe: LCA_OLLAMA_SMOKE is not 1");
        return;
    }
    let workspace = TempDir::new();
    let endpoint = std::env::var("LCA_OLLAMA_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:11434".to_owned());
    let model = std::env::var("LCA_OLLAMA_MODEL").unwrap_or_else(|_| "lca-30b-agent".to_owned());
    let config = workspace.0.join("lca.toml");
    let body = format!(
        "workspace_root = '{}'\n[ollama]\nendpoint = '{endpoint}'\nmodel = '{model}'\nconnect_timeout_secs = 5\nrequest_timeout_secs = 180\ngeneration_limit = 256\n",
        workspace.0.display().to_string().replace('\\', "/")
    );
    fs::write(&config, body).expect("config");
    let output = Command::new(env!("CARGO_BIN_EXE_lca"))
        .args([
            "tools",
            "probe",
            "--protocol",
            "auto",
            "--config",
            config.to_str().expect("utf-8 config path"),
        ])
        .output()
        .expect("run lca");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("validation: passed"), "{stdout}");
    assert!(stdout.contains("execution: disabled"), "{stdout}");
    assert!(stdout.contains("tool: diagnostic_echo"), "{stdout}");
    assert!(
        stdout.starts_with("protocol: native\n") || stdout.starts_with("protocol: json\n"),
        "{stdout}"
    );
    let entries: Vec<_> = fs::read_dir(Path::new(&workspace.0))
        .expect("list")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    assert_eq!(entries.len(), 1, "{entries:?}");
}
