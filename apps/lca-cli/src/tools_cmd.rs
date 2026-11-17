//! Manual filesystem commands.
//!
//! Read commands dispatch a validated action. `patch prepare` prints the diff and then
//! reads one confirmation line from the caller. There is no flag that approves a write.

use std::io::{BufRead, Write};
use std::path::Path;

use lca_config::{AgentConfig, load_from_path};
use lca_core::{WriteConfirmation, commit_prepared, dispatch_validated};
use lca_tools::{
    ActionIdFactory, ActionSource, ApprovalLedger, FsError, FsLimitValues, FsLimits, FsOutcome,
    MutationMode, PrivacyPolicy, ToolRegistry, WorkspaceSandbox, propose_actions, validate_batch,
};
use serde_json::{Value, json};

use crate::{CommandOutput, PatchCommand};

const PATCH_BYTES: u64 = 48 * 1024;

pub(crate) fn run_list(config: &Path, path: Option<&str>) -> CommandOutput {
    run_read_tool(
        config,
        "list_directory",
        json!({"path": path.unwrap_or(".")}),
    )
}

pub(crate) fn run_read(config: &Path, path: &str) -> CommandOutput {
    run_read_tool(config, "read_file", json!({"path": path}))
}

pub(crate) fn run_search(config: &Path, query: &str, path: Option<&str>) -> CommandOutput {
    let mut arguments = serde_json::Map::new();
    arguments.insert("query".to_owned(), Value::String(query.to_owned()));
    if let Some(path) = path {
        arguments.insert("path".to_owned(), Value::String(path.to_owned()));
    }
    run_read_tool(config, "search_files", Value::Object(arguments))
}

/// Prints the prepared diff, then applies it only when stdin repeats the confirmation line.
pub fn run_patch_session<R, W, E>(
    command: &PatchCommand,
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8
where
    R: BufRead,
    W: Write,
    E: Write,
{
    let prepared = match prepare_for_cli(command) {
        Ok(prepared) => prepared,
        Err(message) => return fail(stderr, &message),
    };
    if write_preview(stdout, &prepared).is_err() {
        return 1;
    }
    let mut line = String::new();
    if stdin.read_line(&mut line).is_err() {
        return fail(stderr, "failed to read the approval line");
    }
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    match commit_prepared(
        &prepared.sandbox,
        &prepared.patch,
        WriteConfirmation::TrustedCliLine(line),
        &ApprovalLedger::new(),
    ) {
        Ok(applied) => {
            let _ = writeln!(stdout, "approval: granted");
            let _ = writeln!(stdout, "applied: true");
            let _ = writeln!(stdout, "new_hash: {}", applied.new_hash);
            0
        }
        Err(error) => {
            let _ = writeln!(stdout, "approval: rejected");
            let _ = writeln!(stdout, "applied: false");
            fail(stderr, &error.to_string())
        }
    }
}

struct PreparedSession {
    sandbox: WorkspaceSandbox,
    patch: lca_tools::PreparedPatch,
}

fn prepare_for_cli(command: &PatchCommand) -> Result<PreparedSession, String> {
    let (sandbox, limits) = open_workspace(&command.config)?;
    let bytes = sandbox
        .read_bytes(&command.patch_file, PATCH_BYTES)
        .map_err(|error| error.to_string())?;
    if bytes.contains(&0) {
        return Err("patch file is not text".to_owned());
    }
    let patch = std::str::from_utf8(&bytes).map_err(|_| "patch file is not UTF-8".to_owned())?;
    let path = header_path(patch)?;
    let outcome = dispatch_named(
        &sandbox,
        &limits,
        "apply_patch",
        json!({"path": path, "patch": patch}),
    )?;
    let lca_tools::FsOutcome::Prepared(patch) = outcome else {
        return Err("patch preparation did not return a preview".to_owned());
    };
    Ok(PreparedSession {
        sandbox,
        patch: *patch,
    })
}

fn header_path(patch: &str) -> Result<String, String> {
    let line = patch.lines().next().unwrap_or("");
    let rest = line
        .trim_end_matches('\r')
        .strip_prefix("--- ")
        .ok_or("patch must start with a --- header")?;
    let path = rest.strip_prefix("a/").unwrap_or(rest);
    if path.is_empty() || path == "/dev/null" {
        return Err("patch header does not name a workspace file".to_owned());
    }
    Ok(path.to_owned())
}

fn write_preview(stdout: &mut impl Write, prepared: &PreparedSession) -> std::io::Result<()> {
    writeln!(stdout, "path: {}", prepared.patch.relative_path())?;
    writeln!(stdout, "action_id: {}", prepared.patch.action_id())?;
    writeln!(stdout, "approval: required")?;
    writeln!(stdout, "line_ending: {}", prepared.patch.line_ending())?;
    writeln!(
        stdout,
        "original_hash: {}",
        prepared.patch.original_hash_hex()
    )?;
    writeln!(stdout, "new_hash: {}", prepared.patch.new_hash_hex())?;
    writeln!(
        stdout,
        "confirmation: {}",
        prepared.patch.confirmation_line()
    )?;
    writeln!(stdout, "diff:")?;
    writeln!(stdout, "{}", prepared.patch.diff())?;
    stdout.flush()
}

fn run_read_tool(config: &Path, name: &str, arguments: Value) -> CommandOutput {
    let (sandbox, limits) = match open_workspace(config) {
        Ok(value) => value,
        Err(message) => return failure(&message),
    };
    match dispatch_named(&sandbox, &limits, name, arguments) {
        Ok(outcome) => render_outcome(outcome),
        Err(error) => failure(&error),
    }
}

fn dispatch_named(
    sandbox: &WorkspaceSandbox,
    limits: &FsLimits,
    name: &str,
    arguments: Value,
) -> Result<FsOutcome, String> {
    let registry = ToolRegistry::workspace().map_err(|error| error.to_string())?;
    let proposed = propose_actions(
        &ActionIdFactory::new(),
        ActionSource::Native,
        [(name.to_owned(), arguments)],
    );
    let batch = validate_batch(&registry, &proposed).map_err(|error| error.to_string())?;
    let Some(action) = batch.actions().first() else {
        return Err("tool call was empty".to_owned());
    };
    dispatch_validated(action, sandbox, limits).map_err(|error| error.to_string())
}

fn open_workspace(config: &Path) -> Result<(WorkspaceSandbox, FsLimits), String> {
    let loaded = load_from_path(config).map_err(|error| error.to_string())?;
    let sandbox = sandbox_from(&loaded)?;
    let limits = limits_from(&loaded)?;
    Ok((sandbox, limits))
}

pub(crate) fn sandbox_from(config: &AgentConfig) -> Result<WorkspaceSandbox, String> {
    let privacy = PrivacyPolicy::try_from_patterns(config.privacy_excludes())
        .map_err(|error| error.to_string())?;
    WorkspaceSandbox::with_privacy(config.workspace_root(), privacy)
        .map_err(|error| error.to_string())
}

pub(crate) fn limits_from(config: &AgentConfig) -> Result<FsLimits, String> {
    let mode = match config.mutation_mode() {
        lca_config::MutationMode::ReadOnly => MutationMode::ReadOnly,
        lca_config::MutationMode::PrepareOnly => MutationMode::PrepareOnly,
        lca_config::MutationMode::HumanApproved => MutationMode::HumanApproved,
    };
    let limits = FsLimits::try_new(FsLimitValues {
        read_enabled: config.tool_read_enabled(),
        write_enabled: config.tool_write_enabled(),
        max_file_size_bytes: config.tool_max_file_size_bytes(),
        max_response_bytes: config.tool_max_response_bytes(),
        max_directory_entries: config.tool_max_directory_entries(),
        max_search_matches: config.tool_max_search_matches(),
        max_search_files: config.tool_max_search_files(),
        max_search_total_bytes: config.tool_max_search_total_bytes(),
    })
    .map_err(|error: FsError| error.to_string())?;
    Ok(limits.with_mutation_mode(mode))
}

fn render_outcome(outcome: FsOutcome) -> CommandOutput {
    let mut stdout = String::new();
    match outcome {
        FsOutcome::Listed(list) => {
            push(&mut stdout, "path", &list.path);
            push(
                &mut stdout,
                "truncated",
                if list.truncated { "true" } else { "false" },
            );
            for entry in list.entries {
                match entry.kind.as_str() {
                    "file" => {
                        let size = entry.size.unwrap_or(0);
                        stdout.push_str(&format!("file: {} size={size}\n", entry.path));
                    }
                    "directory" => {
                        stdout.push_str(&format!("directory: {}\n", entry.path));
                    }
                    "reparse" => {
                        stdout.push_str(&format!("reparse: {}\n", entry.path));
                    }
                    _ => {
                        let message = entry.error.unwrap_or_else(|| "unavailable".to_owned());
                        stdout.push_str(&format!("error: {} {message}\n", entry.path));
                    }
                }
            }
        }
        FsOutcome::Read(file) => {
            push(&mut stdout, "path", &file.path);
            push(
                &mut stdout,
                "truncated",
                if file.truncated { "true" } else { "false" },
            );
            push(&mut stdout, "bytes", &file.file_bytes.to_string());
            stdout.push_str("---\n");
            stdout.push_str(&file.content);
            if !file.content.is_empty() && !file.content.ends_with('\n') {
                stdout.push('\n');
            }
        }
        FsOutcome::Searched(result) => {
            push(
                &mut stdout,
                "truncated",
                if result.truncated { "true" } else { "false" },
            );
            push(
                &mut stdout,
                "files_scanned",
                &result.files_scanned.to_string(),
            );
            push(&mut stdout, "skipped", &result.skipped.to_string());
            for hit in result.matches {
                stdout.push_str(&format!("match: {}:{}:{}\n", hit.path, hit.line, hit.text));
            }
        }
        FsOutcome::Prepared(_) | FsOutcome::NotExecuted { .. } => {
            return failure("this command does not prepare or skip a filesystem tool");
        }
    }
    CommandOutput {
        exit_code: 0,
        stdout,
        stderr: String::new(),
    }
}

fn push(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(": ");
    out.push_str(value);
    out.push('\n');
}

fn failure(message: &str) -> CommandOutput {
    CommandOutput {
        exit_code: 1,
        stdout: String::new(),
        stderr: format!("lca: {message}\n"),
    }
}

fn fail(stderr: &mut impl Write, message: &str) -> u8 {
    let _ = writeln!(stderr, "lca: {message}");
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!("lca-cli-patch-{nanos}"));
            std::fs::create_dir_all(&path).expect("temp");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn patch_session_applies_only_the_matching_line() {
        let root = TempDir::new();
        let workspace = root.0.join("ws");
        std::fs::create_dir(&workspace).expect("ws");
        std::fs::write(workspace.join("notes.txt"), "alpha\n").expect("notes");
        std::fs::write(
            workspace.join("edit.diff"),
            "--- a/notes.txt\n+++ b/notes.txt\n@@ -1,1 +1,1 @@\n-alpha\n+beta\n",
        )
        .expect("diff");
        let config = root.0.join("lca.toml");
        let workspace_text = workspace.display().to_string().replace('\\', "/");
        std::fs::write(
            &config,
            format!(
                "workspace_root = '{workspace_text}'\n[tools]\nmutation_mode = 'human_approved'\n"
            ),
        )
        .expect("config");

        let mut rejected_out = Vec::new();
        let mut rejected_err = Vec::new();
        let code = run_patch_session(
            &PatchCommand {
                config: config.clone(),
                patch_file: "edit.diff".to_owned(),
            },
            &mut std::io::Cursor::new(b"no\n".to_vec()),
            &mut rejected_out,
            &mut rejected_err,
        );
        assert_eq!(code, 1);
        let preview = String::from_utf8(rejected_out).expect("utf8");
        assert!(preview.contains("approval: required"), "{preview}");
        assert!(preview.contains("confirmation: approve 1 "), "{preview}");
        assert!(preview.contains("-alpha"), "{preview}");
        assert_eq!(
            std::fs::read_to_string(workspace.join("notes.txt")).expect("unchanged"),
            "alpha\n"
        );

        let line = preview
            .lines()
            .find(|line| line.starts_with("confirmation: "))
            .expect("line")
            .trim_start_matches("confirmation: ")
            .to_owned();
        let mut input = Vec::new();
        input.extend_from_slice(line.as_bytes());
        input.push(b'\n');
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_patch_session(
            &PatchCommand {
                config,
                patch_file: "edit.diff".to_owned(),
            },
            &mut std::io::Cursor::new(input),
            &mut out,
            &mut err,
        );
        let stdout = String::from_utf8(out).expect("utf8");
        let stderr = String::from_utf8(err).expect("utf8");
        assert_eq!(code, 0, "{stdout}\n{stderr}");
        assert!(stdout.contains("applied: true"), "{stdout}");
        assert_eq!(
            std::fs::read_to_string(workspace.join("notes.txt")).expect("applied"),
            "beta\n"
        );
    }
}
