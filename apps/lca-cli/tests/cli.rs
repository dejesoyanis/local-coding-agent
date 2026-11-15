use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "lca-cli-{label}-{}-{nanos}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("address").port();
    drop(listener);
    port
}

fn write_valid_config(workspace: &Path) -> (PathBuf, u16) {
    let port = closed_port();
    let config = workspace.join("lca.toml");
    let body = format!(
        "workspace_root = '{}'\n[ollama]\nendpoint = 'http://127.0.0.1:{port}'\nmodel = 'lca-30b-agent'\nrequest_timeout_secs = 1\n",
        toml_path(workspace)
    );
    fs::write(&config, body).expect("write config");
    (config, port)
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_lca"))
        .args(args)
        .output()
        .expect("run lca")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn status_reports_offline_ollama_without_panicking() {
    let workspace = TempDir::new("status");
    let (config, port) = write_valid_config(workspace.path());
    let output = run(&[
        "status",
        "--config",
        config.to_str().expect("utf-8 config path"),
    ]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stdout}\n{stderr}");
    assert!(stdout.contains("agent_status: idle"), "{stdout}");
    assert!(stdout.contains("config: valid"), "{stdout}");
    assert!(stdout.contains("model: lca-30b-agent"), "{stdout}");
    assert!(
        stdout.contains(&format!("endpoint: http://127.0.0.1:{port}")),
        "{stdout}"
    );
    assert!(stdout.contains("ollama: unavailable"), "{stdout}");
    assert!(stdout.contains("readiness: not_ready"), "{stdout}");
    assert!(stdout.contains("workspace_root:"), "{stdout}");
    assert!(!stdout.contains("workspace_root: unavailable"), "{stdout}");
    let folder = workspace
        .path()
        .file_name()
        .expect("name")
        .to_string_lossy()
        .into_owned();
    assert!(stdout.contains(&folder), "{stdout}");
    assert!(!stdout.to_ascii_lowercase().contains("panic"), "{stdout}");
    assert!(!stderr.to_ascii_lowercase().contains("panic"), "{stderr}");
}

#[test]
fn validate_and_workspace_info_accept_a_closed_ollama_port() {
    let workspace = TempDir::new("validate");
    let (config, _) = write_valid_config(workspace.path());
    let config = config.to_str().expect("utf-8 config path");

    let validate = run(&["config", "validate", "--config", config]);
    let stdout = text(&validate.stdout);
    let stderr = text(&validate.stderr);
    assert_eq!(validate.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("config: valid"), "{stdout}");
    assert!(stdout.contains("model: lca-30b-agent"), "{stdout}");
    assert!(stdout.contains("context_window: 8192"), "{stdout}");
    assert!(stdout.contains("generation_limit: 2048"), "{stdout}");

    let info = run(&["workspace", "info", "--config", config]);
    let stdout = text(&info.stdout);
    let stderr = text(&info.stderr);
    assert_eq!(info.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("exists: true"), "{stdout}");
    assert!(stdout.contains("is_directory: true"), "{stdout}");
}

#[test]
fn validate_uses_lca_toml_in_the_working_directory() {
    let workspace = TempDir::new("default-path");
    let _ = write_valid_config(workspace.path());
    let output = Command::new(env!("CARGO_BIN_EXE_lca"))
        .current_dir(workspace.path())
        .args(["config", "validate"])
        .output()
        .expect("run lca");
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("config: valid"), "{stdout}");
}

#[test]
fn invalid_workspace_roots_are_rejected() {
    let workspace = TempDir::new("invalid");
    let config = workspace.path().join("lca.toml");
    fs::write(
        &config,
        "workspace_root = 'C:/lca-01a-missing-workspace-not-real'\n",
    )
    .expect("write");
    let config = config.to_str().expect("utf-8 config path");

    let validate = run(&["config", "validate", "--config", config]);
    let combined = format!("{}{}", text(&validate.stdout), text(&validate.stderr));
    assert_ne!(validate.status.code(), Some(0), "{combined}");
    assert!(combined.contains("does not exist"), "{combined}");
    assert!(
        !combined.to_ascii_lowercase().contains("panic"),
        "{combined}"
    );

    let info = run(&["workspace", "info", "--config", config]);
    assert_ne!(info.status.code(), Some(0));
    let info_text = format!("{}{}", text(&info.stdout), text(&info.stderr));
    assert!(info_text.contains("does not exist"), "{info_text}");

    let status = run(&["status", "--config", config]);
    let stdout = text(&status.stdout);
    let stderr = text(&status.stderr);
    assert_eq!(status.status.code(), Some(1), "{stdout}\n{stderr}");
    assert!(stdout.contains("config: invalid"), "{stdout}");
    assert!(stdout.contains("ollama: not_checked"), "{stdout}");
    assert!(stdout.contains("readiness: not_ready"), "{stdout}");
    assert!(!stdout.to_ascii_lowercase().contains("panic"), "{stdout}");
}

#[test]
fn embedded_credentials_are_not_printed() {
    let workspace = TempDir::new("secret");
    let config = workspace.path().join("lca.toml");
    let body = format!(
        "workspace_root = '{}'\n[ollama]\nendpoint = 'http://user:super-secret-password@127.0.0.1:11434'\n",
        toml_path(workspace.path())
    );
    fs::write(&config, body).expect("write");
    let config = config.to_str().expect("utf-8 config path");
    let cases: [&[&str]; 2] = [
        &["config", "validate", "--config", config],
        &["status", "--config", config],
    ];

    for args in cases {
        let output = run(args);
        let combined = format!("{}{}", text(&output.stdout), text(&output.stderr));
        assert_ne!(output.status.code(), Some(0), "{combined}");
        assert!(!combined.contains("super-secret-password"), "{combined}");
        assert!(
            !combined.to_ascii_lowercase().contains("panic"),
            "{combined}"
        );
    }
}

#[test]
fn help_and_unknown_commands_do_not_panic() {
    let help = run(&["--help"]);
    let help_text = format!("{}{}", text(&help.stdout), text(&help.stderr));
    assert_eq!(help.status.code(), Some(0), "{help_text}");
    assert!(help_text.contains("status"), "{help_text}");

    let unknown = run(&["not-a-command"]);
    let unknown_text = format!("{}{}", text(&unknown.stdout), text(&unknown.stderr));
    assert_eq!(unknown.status.code(), Some(2), "{unknown_text}");
    assert!(
        !unknown_text.to_ascii_lowercase().contains("panic"),
        "{unknown_text}"
    );
}
