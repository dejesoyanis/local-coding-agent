use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    let cases: [&[&str]; 3] = [
        &["config", "validate", "--config", config],
        &["status", "--config", config],
        &["ask", "--config", config, "hello"],
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
    assert!(help_text.contains("ask"), "{help_text}");

    let unknown = run(&["not-a-command"]);
    let unknown_text = format!("{}{}", text(&unknown.stdout), text(&unknown.stderr));
    assert_eq!(unknown.status.code(), Some(2), "{unknown_text}");
    assert!(
        !unknown_text.to_ascii_lowercase().contains("panic"),
        "{unknown_text}"
    );
}

fn read_http(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 2048];
    let header_end = loop {
        let count = stream.read(&mut temp)?;
        if count == 0 {
            return Ok(buffer);
        }
        buffer.extend_from_slice(&temp[..count]);
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position;
        }
    };
    let headers = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut length = 0_usize;
    for line in headers.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    while buffer.len() < header_end + 4 + length {
        let count = stream.read(&mut temp)?;
        if count == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..count]);
    }
    Ok(buffer)
}

fn serve_once(status: u16, body: &str) -> (String, Arc<Mutex<String>>) {
    let captured = Arc::new(Mutex::new(String::new()));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let captured_thread = Arc::clone(&captured);
    let body = body.to_owned();
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let Ok(request) = read_http(&mut stream) else {
            return;
        };
        *captured_thread.lock().expect("capture") = String::from_utf8_lossy(&request).into_owned();
        let reason = if status == 200 { "OK" } else { "Error" };
        let header = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(body.as_bytes());
    });
    (format!("http://{address}"), captured)
}

fn write_endpoint_config(workspace: &Path, endpoint: &str, timeout: u64) -> PathBuf {
    let config = workspace.join("lca.toml");
    let body = format!(
        "workspace_root = '{}'\n[ollama]\nendpoint = '{endpoint}'\nmodel = 'lca-30b-agent'\nrequest_timeout_secs = {timeout}\nconnect_timeout_secs = 1\n",
        toml_path(workspace)
    );
    fs::write(&config, body).expect("write config");
    config
}

#[test]
fn ask_streams_the_answer_and_does_not_touch_the_workspace() {
    let workspace = TempDir::new("ask");
    let before: Vec<_> = fs::read_dir(workspace.path())
        .expect("list")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    let body = concat!(
        "{\"model\":\"lca-30b-agent\",\"message\":{\"role\":\"assistant\",\"content\":\"Hello\"},\"done\":false}\n",
        "{\"model\":\"lca-30b-agent\",\"message\":{\"role\":\"assistant\",\"content\":\" world\"},\"done\":false}\n",
        "{\"model\":\"lca-30b-agent\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true,\"done_reason\":\"stop\"}\n",
    );
    let (endpoint, captured) = serve_once(200, body);
    let config = write_endpoint_config(workspace.path(), &endpoint, 5);
    let output = run(&[
        "ask",
        "--config",
        config.to_str().expect("utf-8"),
        "--model",
        "override-model",
        "Erkläre mir Rust Ownership",
    ]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    assert_eq!(stdout, "Hello world\n");
    assert!(!stderr.to_ascii_lowercase().contains("debug"), "{stderr}");
    assert!(!stdout.contains("done_reason"), "{stdout}");
    let request = captured.lock().expect("capture").clone();
    assert!(request.contains("override-model"), "{request}");
    assert!(request.contains("\"stream\":true"), "{request}");
    assert!(!request.contains("\"tools\""), "{request}");
    let after: Vec<_> = fs::read_dir(workspace.path())
        .expect("list")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    assert_eq!(before, Vec::<std::ffi::OsString>::new());
    assert_eq!(after.len(), 1, "{after:?}");
}

#[test]
fn ask_reports_runtime_failures_on_stderr() {
    let workspace = TempDir::new("ask-fail");
    let (endpoint, _) = serve_once(500, "{\"error\":\"backend exploded\"}");
    let config = write_endpoint_config(workspace.path(), &endpoint, 5);
    let output = run(&[
        "ask",
        "--config",
        config.to_str().expect("utf-8"),
        "do-not-echo-this-prompt",
    ]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stdout}\n{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("lca:"), "{stderr}");
    assert!(stderr.contains("backend exploded"), "{stderr}");
    assert!(!stderr.contains("do-not-echo-this-prompt"), "{stderr}");
    assert!(!stderr.to_ascii_lowercase().contains("panic"), "{stderr}");

    let refused = write_endpoint_config(
        workspace.path(),
        &format!("http://127.0.0.1:{}", closed_port()),
        1,
    );
    let output = run(&["ask", "--config", refused.to_str().expect("utf-8"), "hello"]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(text(&output.stdout).is_empty());
    assert!(stderr.contains("lca:"), "{stderr}");
}

#[test]
fn ask_rejects_an_empty_prompt_and_a_remote_endpoint_without_waiting() {
    let workspace = TempDir::new("ask-guard");
    let config = write_endpoint_config(workspace.path(), "http://192.0.2.10:11434", 30);
    let config = config.to_str().expect("utf-8");

    let started = Instant::now();
    let empty = run(&["ask", "--config", config, "   "]);
    assert!(started.elapsed() < Duration::from_millis(1500));
    let stderr = text(&empty.stderr);
    assert_eq!(empty.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("prompt must not be empty"), "{stderr}");

    let started = Instant::now();
    let remote = run(&["ask", "--config", config, "hello"]);
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "{:?}",
        started.elapsed()
    );
    let stderr = text(&remote.stderr);
    assert_eq!(remote.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("loopback"), "{stderr}");
    assert!(text(&remote.stdout).is_empty(), "{}", text(&remote.stdout));
}

#[test]
fn tools_probe_rejects_an_unknown_protocol() {
    let output = run(&["tools", "probe", "--protocol", "yaml"]);
    let combined = format!("{}{}", text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(2), "{combined}");
    assert!(
        combined.to_ascii_lowercase().contains("protocol"),
        "{combined}"
    );
    assert!(
        !combined.to_ascii_lowercase().contains("panic"),
        "{combined}"
    );
}

#[test]
fn tools_probe_validates_a_native_call_against_a_mock_backend() {
    let workspace = TempDir::new("probe");
    let before: Vec<_> = fs::read_dir(workspace.path())
        .expect("list")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    let show = r#"{"capabilities":["completion","tools"],"details":{"family":"test"}}"#;
    let chat = r#"{"model":"lca-30b-agent","message":{"role":"assistant","content":"<tool_call>diagnostic_echo</tool_call>","tool_calls":[{"id":"model-id","function":{"name":"diagnostic_echo","arguments":{"message":"hello"}}}]},"done":true,"done_reason":"stop"}"#;
    let (endpoint, captured) =
        serve_routes(&[("POST /api/show", 200, show), ("POST /api/chat", 200, chat)]);
    let config = write_endpoint_config(workspace.path(), &endpoint, 5);
    let output = run(&[
        "tools",
        "probe",
        "--protocol",
        "native",
        "--config",
        config.to_str().expect("utf-8"),
    ]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    assert_eq!(
        stdout,
        "protocol: native\ntool: diagnostic_echo\nvalidation: passed\nexecution: disabled\n"
    );
    let requests = captured.lock().expect("capture").clone();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(requests[0].contains("POST /api/show"), "{}", requests[0]);
    assert!(requests[1].contains("POST /api/chat"), "{}", requests[1]);
    assert!(requests[1].contains("\"stream\":false"), "{}", requests[1]);
    assert!(requests[1].contains("diagnostic_echo"), "{}", requests[1]);
    assert!(!requests[1].contains("\"format\""), "{}", requests[1]);
    let after: Vec<_> = fs::read_dir(workspace.path())
        .expect("list")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    assert_eq!(before, Vec::<std::ffi::OsString>::new());
    assert_eq!(after.len(), 1, "{after:?}");
}

fn serve_routes(routes: &[(&str, u16, &str)]) -> (String, Arc<Mutex<Vec<String>>>) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    listener.set_nonblocking(true).expect("nonblocking");
    let captured_thread = Arc::clone(&captured);
    let routes: Vec<(String, u16, String)> = routes
        .iter()
        .map(|(path, status, body)| ((*path).to_owned(), *status, (*body).to_owned()))
        .collect();
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut served = 0;
        while served < routes.len() && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let Ok(request) = read_http(&mut stream) else {
                        continue;
                    };
                    let text = String::from_utf8_lossy(&request).into_owned();
                    let (status, body) = routes
                        .iter()
                        .find(|(path, _, _)| text.contains(path))
                        .map(|(_, status, body)| (*status, body.as_str()))
                        .unwrap_or((500, ""));
                    captured_thread.lock().expect("capture").push(text);
                    let reason = if status == 200 { "OK" } else { "Error" };
                    let header = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    let _ = stream.write_all(body.as_bytes());
                    served += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://{address}"), captured)
}

#[test]
fn filesystem_commands_stay_inside_the_workspace() {
    let workspace = TempDir::new("fs-cli");
    fs::create_dir(workspace.path().join("src")).expect("src");
    fs::write(workspace.path().join("notes.txt"), "alpha\n").expect("notes");
    fs::write(
        workspace.path().join("src").join("lib.rs"),
        "pub trait ModelRuntime {}\n",
    )
    .expect("lib");
    let (config, _) = write_valid_config(workspace.path());
    let config = config.to_str().expect("utf-8 config path");

    let list = run(&["tools", "list", "--config", config]);
    let stdout = text(&list.stdout);
    let stderr = text(&list.stderr);
    assert_eq!(list.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("file: notes.txt"), "{stdout}");
    assert!(stdout.contains("directory: src"), "{stdout}");

    let read = run(&["tools", "read", "notes.txt", "--config", config]);
    let stdout = text(&read.stdout);
    let stderr = text(&read.stderr);
    assert_eq!(read.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("alpha"), "{stdout}");
    assert!(stdout.contains("truncated: false"), "{stdout}");

    let search = run(&[
        "tools",
        "search",
        "ModelRuntime",
        "--path",
        "src",
        "--config",
        config,
    ]);
    let stdout = text(&search.stdout);
    let stderr = text(&search.stderr);
    assert_eq!(search.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("match: src/lib.rs:1:"), "{stdout}");

    let outside = run(&["tools", "read", "../notes.txt", "--config", config]);
    assert_ne!(outside.status.code(), Some(0));
    let combined = format!("{}{}", text(&outside.stdout), text(&outside.stderr));
    assert!(!combined.contains("alpha"), "{combined}");

    let flagged = run(&[
        "tools",
        "patch",
        "prepare",
        "--yes",
        "edit.diff",
        "--config",
        config,
    ]);
    assert_ne!(flagged.status.code(), Some(0));

    fs::write(
        workspace.path().join("edit.diff"),
        "--- a/notes.txt\n+++ b/notes.txt\n@@ -1,1 +1,1 @@\n-alpha\n+beta\n",
    )
    .expect("diff");
    let mut rejected = Command::new(env!("CARGO_BIN_EXE_lca"))
        .args(["tools", "patch", "prepare", "edit.diff", "--config", config])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    {
        let mut stdin = rejected.stdin.take().expect("stdin");
        stdin.write_all(b"no\n").expect("write stdin");
    }
    let output = rejected.wait_with_output().expect("wait");
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_ne!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("approval: required"), "{stdout}");
    assert!(stdout.contains("applied: false"), "{stdout}");
    assert_eq!(
        fs::read_to_string(workspace.path().join("notes.txt")).expect("unchanged"),
        "alpha\n"
    );
}

fn encode_json_string(value: &str) -> String {
    let mut encoded = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => encoded.push_str("\\\\"),
            '"' => encoded.push_str("\\\""),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            character if character.is_control() => {
                encoded.push_str(&format!("\\u{:04x}", u32::from(character)));
            }
            character => encoded.push(character),
        }
    }
    encoded.push('"');
    encoded
}

fn chat_response(content: &str, calls: &[(&str, &str)]) -> String {
    let calls_json = if calls.is_empty() {
        "[]".to_owned()
    } else {
        let parts: Vec<String> = calls
            .iter()
            .map(|(name, arguments)| {
                format!(
                    r#"{{"function":{{"name":{},"arguments":{arguments}}}}}"#,
                    encode_json_string(name)
                )
            })
            .collect();
        format!("[{}]", parts.join(","))
    };
    format!(
        r#"{{"model":"lca-30b-agent","message":{{"role":"assistant","content":{},"tool_calls":{calls_json}}},"done":true,"done_reason":"stop"}}"#,
        encode_json_string(content)
    )
}

#[test]
fn agent_run_reads_a_file_from_one_native_model_call() {
    let workspace = TempDir::new("agent-read");
    fs::write(workspace.path().join("notes.txt"), "alpha\n").expect("notes");
    let show = r#"{"capabilities":["completion","tools"]}"#;
    let chat = chat_response("", &[("read_file", r#"{"path":"notes.txt"}"#)]);
    let (endpoint, captured) = serve_routes(&[
        ("POST /api/show", 200, show),
        ("POST /api/chat", 200, &chat),
    ]);
    let config = write_endpoint_config(workspace.path(), &endpoint, 5);
    let output = run(&[
        "agent",
        "run",
        "--config",
        config.to_str().expect("utf-8"),
        "Lies notes.txt",
    ]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("protocol: native\n"), "{stdout}");
    assert!(stdout.contains("model_calls: 1\n"), "{stdout}");
    assert!(stdout.contains("tool: read_file\n"), "{stdout}");
    assert!(stdout.contains("result: read\n"), "{stdout}");
    assert!(stdout.contains("alpha\n"), "{stdout}");
    let requests = captured.lock().expect("capture").clone();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(requests[0].contains("POST /api/show"), "{}", requests[0]);
    assert!(requests[1].contains("POST /api/chat"), "{}", requests[1]);
    assert!(requests[1].contains("\"stream\":false"), "{}", requests[1]);
    assert!(!requests[1].contains("\"format\""), "{}", requests[1]);
    for name in ["list_directory", "read_file", "search_files", "apply_patch"] {
        assert!(
            requests[1].contains(name),
            "{name} missing in {}",
            requests[1]
        );
    }
    assert!(!requests[1].contains("diagnostic_echo"), "{}", requests[1]);
    assert!(!requests[1].contains("execute_command"), "{}", requests[1]);
}

#[test]
fn agent_run_does_not_execute_text_that_looks_like_a_tool_call() {
    let workspace = TempDir::new("agent-text");
    fs::write(workspace.path().join("secret.txt"), "SENTINEL_DO_NOT_LEAK").expect("secret");
    let show = r#"{"capabilities":["completion","tools"]}"#;
    let document = r#"{"protocol_version":1,"actions":[{"tool":"read_file","arguments":{"path":"secret.txt"}}]}"#;
    let chat = chat_response(document, &[]);
    let (endpoint, captured) = serve_routes(&[
        ("POST /api/show", 200, show),
        ("POST /api/chat", 200, &chat),
    ]);
    let config = write_endpoint_config(workspace.path(), &endpoint, 5);
    let output = run(&[
        "agent",
        "run",
        "--protocol",
        "native",
        "--config",
        config.to_str().expect("utf-8"),
        "Lies secret.txt",
    ]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("actions: 0\n"), "{stdout}");
    assert!(!stdout.contains("SENTINEL_DO_NOT_LEAK"), "{stdout}");
    assert!(!stderr.contains("SENTINEL_DO_NOT_LEAK"), "{stderr}");
    assert_eq!(captured.lock().expect("capture").len(), 2);
}

#[test]
fn agent_run_prepares_a_patch_without_writing() {
    let workspace = TempDir::new("agent-patch");
    fs::write(workspace.path().join("notes.txt"), "alpha\n").expect("notes");
    let show = r#"{"capabilities":["completion","tools"]}"#;
    let patch = "--- a/notes.txt\n+++ b/notes.txt\n@@ -1,1 +1,1 @@\n-alpha\n+beta\n";
    let arguments = format!(
        r#"{{"path":"notes.txt","patch":{}}}"#,
        encode_json_string(patch)
    );
    let chat = chat_response("approve 1 please", &[("apply_patch", &arguments)]);
    let (endpoint, captured) = serve_routes(&[
        ("POST /api/show", 200, show),
        ("POST /api/chat", 200, &chat),
    ]);
    let config = write_endpoint_config(workspace.path(), &endpoint, 5);
    let output = run(&[
        "agent",
        "run",
        "--config",
        config.to_str().expect("utf-8"),
        "Andere notes.txt",
    ]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("result: prepared\n"), "{stdout}");
    assert!(stdout.contains("approval: required\n"), "{stdout}");
    assert!(stdout.contains("applied: false\n"), "{stdout}");
    assert!(stdout.contains("-alpha"), "{stdout}");
    assert_eq!(
        fs::read_to_string(workspace.path().join("notes.txt")).expect("unchanged"),
        "alpha\n"
    );
    assert_eq!(captured.lock().expect("capture").len(), 2);
}

#[test]
fn agent_run_rejects_an_unknown_tool_without_leaking_arguments() {
    let workspace = TempDir::new("agent-unknown");
    fs::write(workspace.path().join("secret.txt"), "SENTINEL_DO_NOT_LEAK").expect("secret");
    let show = r#"{"capabilities":["completion","tools"]}"#;
    let chat = chat_response(
        "",
        &[("execute_command", r#"{"command":"SENTINEL_DO_NOT_LEAK"}"#)],
    );
    let (endpoint, _) = serve_routes(&[
        ("POST /api/show", 200, show),
        ("POST /api/chat", 200, &chat),
    ]);
    let config = write_endpoint_config(workspace.path(), &endpoint, 5);
    let output = run(&[
        "agent",
        "run",
        "--config",
        config.to_str().expect("utf-8"),
        "do something",
    ]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stdout}\n{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("unknown tool"), "{stderr}");
    assert!(!stderr.contains("SENTINEL_DO_NOT_LEAK"), "{stderr}");
    assert!(!stdout.contains("SENTINEL_DO_NOT_LEAK"), "{stdout}");
}

#[test]
fn agent_run_json_fallback_reads_from_the_document_only() {
    let workspace = TempDir::new("agent-json");
    fs::write(workspace.path().join("notes.txt"), "alpha\n").expect("notes");
    fs::write(workspace.path().join("secret.txt"), "SENTINEL_DO_NOT_LEAK").expect("secret");
    let show = r#"{"capabilities":["completion","json"]}"#;
    let document = r#"{"protocol_version":1,"actions":[{"tool":"read_file","arguments":{"path":"notes.txt"}}]}"#;
    let native = r#"{"function":{"name":"read_file","arguments":{"path":"secret.txt"}}}"#;
    let chat = format!(
        r#"{{"model":"lca-30b-agent","message":{{"role":"assistant","content":{},"tool_calls":[{native}]}},"done":true,"done_reason":"stop"}}"#,
        encode_json_string(document)
    );
    let (endpoint, captured) = serve_routes(&[
        ("POST /api/show", 200, show),
        ("POST /api/chat", 200, &chat),
    ]);
    let config = write_endpoint_config(workspace.path(), &endpoint, 5);
    let output = run(&[
        "agent",
        "run",
        "--protocol",
        "json",
        "--config",
        config.to_str().expect("utf-8"),
        "Lies notes.txt",
    ]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("protocol: json\n"), "{stdout}");
    assert!(stdout.contains("source: json\n"), "{stdout}");
    assert!(stdout.contains("alpha\n"), "{stdout}");
    assert!(!stdout.contains("SENTINEL_DO_NOT_LEAK"), "{stdout}");
    let requests = captured.lock().expect("capture").clone();
    assert_eq!(requests.len(), 2, "{requests:?}");
    assert!(
        requests[1].contains("\"format\":\"json\""),
        "{}",
        requests[1]
    );
    assert!(!requests[1].contains("\"tools\""), "{}", requests[1]);
    assert!(requests[1].contains("protocol_version"), "{}", requests[1]);
    assert!(requests[1].contains("\"stream\":false"), "{}", requests[1]);
}

#[test]
fn agent_run_stops_at_the_configured_action_limit() {
    let workspace = TempDir::new("agent-limit");
    fs::write(workspace.path().join("notes.txt"), "alpha\n").expect("notes");
    fs::write(workspace.path().join("secret.txt"), "SENTINEL_DO_NOT_LEAK").expect("secret");
    let show = r#"{"capabilities":["completion","tools"]}"#;
    let chat = chat_response(
        "",
        &[
            ("read_file", r#"{"path":"notes.txt"}"#),
            ("read_file", r#"{"path":"secret.txt"}"#),
        ],
    );
    let (endpoint, captured) = serve_routes(&[
        ("POST /api/show", 200, show),
        ("POST /api/chat", 200, &chat),
    ]);
    let config = workspace.path().join("lca.toml");
    let body = format!(
        "workspace_root = '{}'\n[ollama]\nendpoint = '{endpoint}'\nmodel = 'lca-30b-agent'\nrequest_timeout_secs = 5\nconnect_timeout_secs = 1\n[limits]\nmax_steps = 1\n",
        toml_path(workspace.path())
    );
    fs::write(&config, body).expect("config");
    let output = run(&[
        "agent",
        "run",
        "--config",
        config.to_str().expect("utf-8"),
        "Lies beide Dateien",
    ]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stdout}\n{stderr}");
    assert!(stderr.contains("limit is 1"), "{stderr}");
    assert!(!stdout.contains("alpha"), "{stdout}");
    assert!(!stdout.contains("SENTINEL_DO_NOT_LEAK"), "{stdout}");
    assert!(!stderr.contains("SENTINEL_DO_NOT_LEAK"), "{stderr}");
    assert_eq!(captured.lock().expect("capture").len(), 2);
}

#[test]
fn agent_run_does_not_retry_a_failed_generation() {
    let workspace = TempDir::new("agent-retry");
    let show = r#"{"capabilities":["completion","tools"]}"#;
    let (endpoint, captured) = serve_routes(&[
        ("POST /api/show", 200, show),
        ("POST /api/chat", 500, "{\"error\":\"backend exploded\"}"),
    ]);
    let config = write_endpoint_config(workspace.path(), &endpoint, 2);
    let output = run(&[
        "agent",
        "run",
        "--config",
        config.to_str().expect("utf-8"),
        "do-not-echo-this-prompt",
    ]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stdout}\n{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(stderr.contains("backend exploded"), "{stderr}");
    assert!(!stderr.contains("do-not-echo-this-prompt"), "{stderr}");
    assert_eq!(captured.lock().expect("capture").len(), 2);
}

#[test]
fn agent_run_rejects_an_empty_prompt_and_an_unknown_protocol() {
    let workspace = TempDir::new("agent-guard");
    let config = write_endpoint_config(workspace.path(), "http://192.0.2.10:11434", 30);
    let config = config.to_str().expect("utf-8");
    let started = Instant::now();
    let empty = run(&["agent", "run", "--config", config, "   "]);
    assert!(started.elapsed() < Duration::from_millis(1500));
    let stderr = text(&empty.stderr);
    assert_eq!(empty.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("prompt must not be empty"), "{stderr}");
    assert!(text(&empty.stdout).is_empty());

    let unknown = run(&[
        "agent",
        "run",
        "--protocol",
        "yaml",
        "--config",
        config,
        "hello",
    ]);
    let combined = format!("{}{}", text(&unknown.stdout), text(&unknown.stderr));
    assert_eq!(unknown.status.code(), Some(2), "{combined}");
    assert!(
        combined.to_ascii_lowercase().contains("protocol"),
        "{combined}"
    );
}

#[test]
fn eval_tools_writes_a_read_only_report_and_does_not_leak_protected_bytes() {
    let workspace = TempDir::new("eval");
    fs::write(
        workspace.path().join("Cargo.toml"),
        "[package]\nname = \"demo\"\n",
    )
    .expect("cargo");
    fs::create_dir(workspace.path().join("crates")).expect("crates");
    fs::write(
        workspace.path().join("crates").join("lib.rs"),
        "pub struct ModelRuntime;\n",
    )
    .expect("lib");
    fs::write(workspace.path().join("notes.txt"), "alpha\n").expect("notes");
    let show = r#"{"capabilities":["completion","tools"]}"#;
    let chat = chat_response("hello", &[]);
    let version = r#"{"version":"0.0.0-test"}"#;
    let tags = r#"{"models":[{"name":"lca-30b-agent:latest","digest":"sha256:abc"}]}"#;
    let mut routes = Vec::new();
    for _ in 0..4 {
        routes.push(("GET /api/version", 200, version));
        routes.push(("GET /api/tags", 200, tags));
        routes.push(("POST /api/show", 200, show));
        routes.push(("POST /api/chat", 200, chat.as_str()));
    }
    let (endpoint, _captured) = serve_routes(&routes);
    let config = write_endpoint_config(workspace.path(), &endpoint, 5);
    fs::write(workspace.path().join(".env"), "SENTINEL_DO_NOT_LEAK\n").expect("env");
    let report_path = workspace.path().join("eval-report.json");
    let output = run(&[
        "eval",
        "tools",
        "--runs",
        "1",
        "--protocol",
        "native",
        "--output",
        report_path.to_str().expect("utf-8 report"),
        "--config",
        config.to_str().expect("utf-8"),
    ]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}\n{stderr}");
    assert!(stdout.contains("execution: live\n"), "{stdout}");
    assert!(stdout.contains("write_enabled: false\n"), "{stdout}");
    assert!(
        stdout.contains("prompt_version: lca-01e-h1.1\n"),
        "{stdout}"
    );
    let report = fs::read_to_string(&report_path).expect("report");
    assert!(report.contains("\"execution\": \"live\""), "{report}");
    assert!(report.contains("\"write_enabled\": false"), "{report}");
    assert!(report.contains("sha256:abc"), "{report}");
    assert!(!report.contains("SENTINEL_DO_NOT_LEAK"), "{report}");
    assert!(!stdout.contains("SENTINEL_DO_NOT_LEAK"), "{stdout}");
    assert_eq!(
        fs::read_to_string(workspace.path().join("notes.txt")).expect("notes"),
        "alpha\n"
    );
    assert_eq!(
        fs::read_to_string(workspace.path().join(".env")).expect("env"),
        "SENTINEL_DO_NOT_LEAK\n"
    );
}
