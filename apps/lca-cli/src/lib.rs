//! Command-line composition root for the local coding agent foundation.
//!
//! `status`, `config validate`, `workspace info`, and `tools probe` load configuration.
//! Status probes Ollama and reports an unavailable server without panicking. `tools probe`
//! validates a structured tool call and does not execute it. `tools list`, `tools read`,
//! and `tools search` run inside the workspace sandbox. `tools patch prepare` writes only
//! after a confirmation line read in that same process. This binary does not start an
//! agent loop and does not run a shell.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod ask;
mod probe;
mod tools_cmd;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use lca_config::{AgentConfig, ConfigError, load_from_path};
use lca_core::AgentLifecycle;
use lca_model_runtime::ProtocolPreference;
use lca_ollama::{HttpOllamaClient, OllamaAvailability, OllamaClient};

/// Text produced by one invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Process exit code.
    pub exit_code: u8,
    /// Standard output, ending in a newline when it is not empty.
    pub stdout: String,
    /// Standard error, ending in a newline when it is not empty.
    pub stderr: String,
}

/// Installs a stderr tracing subscriber. Missing `RUST_LOG` stays at warn.
///
/// The default level does not record configuration file contents. Callers that set
/// `RUST_LOG` still only receive the structured fields emitted by the libraries.
pub fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// Parsed invocation. `Ask` is streamed by the binary; the other commands are buffered.
#[derive(Debug)]
pub enum Invocation {
    /// A command whose entire output is available before the process writes it.
    Buffered(CommandOutput),
    /// A prompt that must be streamed to the caller's stdout.
    Ask(AskCommand),
    /// A patch preview that must be shown before the confirmation line is read.
    Patch(PatchCommand),
}

/// Arguments for `lca tools patch prepare`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchCommand {
    /// Configuration file selected by `--config`, or `lca.toml`.
    pub config: PathBuf,
    /// Workspace-relative unified diff.
    pub patch_file: String,
}

/// Arguments for `lca ask`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskCommand {
    /// Configuration file selected by `--config`, or `lca.toml`.
    pub config: PathBuf,
    /// Model override from `--model`.
    pub model: Option<String>,
    /// Prompt text, before trimming.
    pub prompt: String,
}

/// Parses `args` (including argv0) without running a model.
pub fn interpret<I, S>(args: I) -> Invocation
where
    I: IntoIterator<Item = S>,
    S: Into<OsString> + Clone,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => return Invocation::Buffered(clap_output(error)),
    };
    let config_path = cli.config.unwrap_or_else(|| PathBuf::from("lca.toml"));
    match cli.command {
        Command::Status => Invocation::Buffered(status(&config_path)),
        Command::Config {
            action: ConfigAction::Validate,
        } => Invocation::Buffered(validate(&config_path)),
        Command::Workspace {
            action: WorkspaceAction::Info,
        } => Invocation::Buffered(workspace_info(&config_path)),
        Command::Ask { model, prompt } => Invocation::Ask(AskCommand {
            config: config_path,
            model,
            prompt,
        }),
        Command::Tools { action } => match action {
            ToolsAction::Probe { protocol } => {
                Invocation::Buffered(probe::run_probe(&probe::ProbeCommand {
                    config: config_path,
                    protocol: protocol.preference(),
                }))
            }
            ToolsAction::List { path } => {
                Invocation::Buffered(tools_cmd::run_list(&config_path, path.as_deref()))
            }
            ToolsAction::Read { path } => {
                Invocation::Buffered(tools_cmd::run_read(&config_path, &path))
            }
            ToolsAction::Search { query, path } => {
                Invocation::Buffered(tools_cmd::run_search(&config_path, &query, path.as_deref()))
            }
            ToolsAction::Patch {
                action: PatchAction::Prepare { patch_file },
            } => Invocation::Patch(PatchCommand {
                config: config_path,
                patch_file,
            }),
        },
    }
}

/// Parses `args` and runs a buffered command.
///
/// `ask` is rejected here because this function would have to hold the whole answer.
/// The `lca` binary streams that command instead.
pub fn dispatch<I, S>(args: I) -> CommandOutput
where
    I: IntoIterator<Item = S>,
    S: Into<OsString> + Clone,
{
    match interpret(args) {
        Invocation::Buffered(output) => output,
        Invocation::Ask(_) => CommandOutput {
            exit_code: 2,
            stdout: String::new(),
            stderr: "lca: ask is streamed by the lca binary\n".to_owned(),
        },
        Invocation::Patch(_) => CommandOutput {
            exit_code: 2,
            stdout: String::new(),
            stderr: "lca: patch prepare is confirmed by the lca binary\n".to_owned(),
        },
    }
}

pub use ask::run_ask;
pub use tools_cmd::run_patch_session;

#[derive(Debug, Parser)]
#[command(
    name = "lca",
    version,
    about = "Local coding agent foundation",
    arg_required_else_help = true
)]
struct Cli {
    /// TOML configuration file. Defaults to lca.toml in the working directory.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show the agent state, model, endpoint, workspace, and Ollama readiness.
    Status,
    /// Inspect configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Inspect the configured workspace.
    Workspace {
        #[command(subcommand)]
        action: WorkspaceAction,
    },
    /// Stream an answer from the configured local model.
    Ask {
        /// Model name. Overrides the configuration file for this call.
        #[arg(long, value_name = "NAME")]
        model: Option<String>,
        /// Prompt text.
        #[arg(value_name = "PROMPT")]
        prompt: String,
    },
    /// Probe tool calling or run a workspace filesystem tool.
    Tools {
        #[command(subcommand)]
        action: ToolsAction,
    },
}

#[derive(Debug, Subcommand)]
enum ToolsAction {
    /// Ask the model for diagnostic_echo and validate the proposal.
    Probe {
        /// `native`, `json`, or `auto`. The default is `auto`.
        #[arg(long, value_enum, default_value = "auto")]
        protocol: CliProtocol,
    },
    /// List one workspace directory. The listing is not recursive.
    List {
        /// Workspace-relative directory. Defaults to `.`.
        path: Option<String>,
    },
    /// Read one UTF-8 file inside the workspace.
    Read {
        /// Workspace-relative path.
        path: String,
    },
    /// Search workspace text for a literal query.
    Search {
        /// Literal text. Regular expressions are not evaluated.
        query: String,
        /// Workspace-relative directory. Defaults to `.`.
        #[arg(long, value_name = "PATH")]
        path: Option<String>,
    },
    /// Prepare a single-file patch and ask for approval.
    Patch {
        #[command(subcommand)]
        action: PatchAction,
    },
}

#[derive(Debug, Subcommand)]
enum PatchAction {
    /// Show the diff and require an action-bound confirmation on stdin.
    Prepare {
        /// Workspace-relative unified diff.
        patch_file: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum CliProtocol {
    /// Native tool calls. Requires a confirmed backend capability.
    Native,
    /// Versioned JSON action document.
    Json,
    /// Native when confirmed, otherwise the JSON document.
    Auto,
}

impl CliProtocol {
    const fn preference(self) -> ProtocolPreference {
        match self {
            Self::Native => ProtocolPreference::Native,
            Self::Json => ProtocolPreference::StructuredJson,
            Self::Auto => ProtocolPreference::Auto,
        }
    }
}

#[derive(Debug, Subcommand)]
enum ConfigAction {
    /// Load the configuration file and report validation errors.
    Validate,
}

#[derive(Debug, Subcommand)]
enum WorkspaceAction {
    /// Print the canonical workspace root.
    Info,
}

fn status(config_path: &Path) -> CommandOutput {
    // LCA-01A has no agent loop. Status reports the initial lifecycle state only.
    let agent_status = AgentLifecycle::new().status();
    match load_from_path(config_path) {
        Ok(config) => {
            let availability = probe(&config);
            let ready = matches!(availability, OllamaAvailability::Ready { .. });
            let mut stdout = String::new();
            push_line(&mut stdout, "agent_status", agent_status.as_str());
            push_line(&mut stdout, "config", "valid");
            push_line(&mut stdout, "config_file", &display_path(config_path));
            push_line(&mut stdout, "model", config.model());
            push_line(&mut stdout, "endpoint", config.endpoint());
            push_line(
                &mut stdout,
                "workspace_root",
                &config.workspace_root().display().to_string(),
            );
            push_line(
                &mut stdout,
                "context_window",
                &config.context_window().to_string(),
            );
            push_line(
                &mut stdout,
                "generation_limit",
                &config.generation_limit().to_string(),
            );
            push_line(&mut stdout, "max_steps", &config.max_steps().to_string());
            push_line(
                &mut stdout,
                "timeout_secs",
                &config.timeout().as_secs().to_string(),
            );
            push_line(
                &mut stdout,
                "request_timeout_secs",
                &config.request_timeout().as_secs().to_string(),
            );
            push_line(
                &mut stdout,
                "connect_timeout_secs",
                &config.connect_timeout().as_secs().to_string(),
            );
            push_line(&mut stdout, "ollama", availability.as_str());
            push_line(
                &mut stdout,
                "ollama_detail",
                &availability.detail(config.model()),
            );
            push_line(
                &mut stdout,
                "readiness",
                if ready { "ready" } else { "not_ready" },
            );
            CommandOutput {
                exit_code: if ready { 0 } else { 1 },
                stdout,
                stderr: String::new(),
            }
        }
        Err(error) => {
            tracing::debug!(error_kind = error.kind(), "status configuration rejected");
            let mut stdout = String::new();
            push_line(&mut stdout, "agent_status", agent_status.as_str());
            push_line(&mut stdout, "config", "invalid");
            push_line(&mut stdout, "config_file", &display_path(config_path));
            push_line(&mut stdout, "config_detail", &error.to_string());
            push_line(&mut stdout, "model", "unavailable");
            push_line(&mut stdout, "endpoint", "unavailable");
            push_line(&mut stdout, "workspace_root", "unavailable");
            push_line(&mut stdout, "ollama", "not_checked");
            push_line(
                &mut stdout,
                "ollama_detail",
                "configuration is invalid; endpoint was not contacted",
            );
            push_line(&mut stdout, "readiness", "not_ready");
            CommandOutput {
                exit_code: 1,
                stdout,
                stderr: String::new(),
            }
        }
    }
}

fn validate(config_path: &Path) -> CommandOutput {
    match load_from_path(config_path) {
        Ok(config) => {
            let mut stdout = String::new();
            push_summary(&mut stdout, config_path, &config);
            CommandOutput {
                exit_code: 0,
                stdout,
                stderr: String::new(),
            }
        }
        Err(error) => error_output(&error),
    }
}

fn workspace_info(config_path: &Path) -> CommandOutput {
    match load_from_path(config_path) {
        Ok(config) => {
            let mut stdout = String::new();
            push_line(&mut stdout, "config_file", &display_path(config_path));
            push_line(
                &mut stdout,
                "workspace_root",
                &config.workspace_root().display().to_string(),
            );
            push_line(&mut stdout, "exists", "true");
            push_line(&mut stdout, "is_directory", "true");
            CommandOutput {
                exit_code: 0,
                stdout,
                stderr: String::new(),
            }
        }
        Err(error) => error_output(&error),
    }
}

fn push_summary(out: &mut String, config_path: &Path, config: &AgentConfig) {
    push_line(out, "config", "valid");
    push_line(out, "config_file", &display_path(config_path));
    push_line(
        out,
        "workspace_root",
        &config.workspace_root().display().to_string(),
    );
    push_line(out, "model", config.model());
    push_line(out, "endpoint", config.endpoint());
    push_line(out, "context_window", &config.context_window().to_string());
    push_line(
        out,
        "generation_limit",
        &config.generation_limit().to_string(),
    );
    push_line(out, "max_steps", &config.max_steps().to_string());
    push_line(out, "timeout_secs", &config.timeout().as_secs().to_string());
    push_line(
        out,
        "request_timeout_secs",
        &config.request_timeout().as_secs().to_string(),
    );
    push_line(
        out,
        "connect_timeout_secs",
        &config.connect_timeout().as_secs().to_string(),
    );
    push_line(
        out,
        "loopback_endpoint",
        if config.loopback_endpoint() {
            "true"
        } else {
            "false"
        },
    );
    push_line(
        out,
        "tool_read_enabled",
        if config.tool_read_enabled() {
            "true"
        } else {
            "false"
        },
    );
    push_line(
        out,
        "tool_write_enabled",
        if config.tool_write_enabled() {
            "true"
        } else {
            "false"
        },
    );
    push_line(out, "require_write_approval", "true");
    push_line(
        out,
        "max_file_size_bytes",
        &config.tool_max_file_size_bytes().to_string(),
    );
}

fn probe(config: &AgentConfig) -> OllamaAvailability {
    match HttpOllamaClient::new(config.endpoint(), config.request_timeout()) {
        Ok(client) => client.check_model(config.model()),
        Err(error) => OllamaAvailability::Unavailable {
            message: error.to_string(),
        },
    }
}

fn error_output(error: &ConfigError) -> CommandOutput {
    tracing::debug!(error_kind = error.kind(), "command rejected configuration");
    CommandOutput {
        exit_code: 1,
        stdout: String::new(),
        stderr: format!("lca: {error}\n"),
    }
}

fn clap_output(error: clap::Error) -> CommandOutput {
    let code = u8::try_from(error.exit_code()).unwrap_or(2);
    let message = finish_line(error.to_string());
    if error.use_stderr() {
        CommandOutput {
            exit_code: code,
            stdout: String::new(),
            stderr: message,
        }
    } else {
        CommandOutput {
            exit_code: code,
            stdout: message,
            stderr: String::new(),
        }
    }
}

fn push_line(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(": ");
    out.push_str(value);
    out.push('\n');
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

fn finish_line(mut text: String) -> String {
    if text.is_empty() || text.ends_with('\n') {
        text
    } else {
        text.push('\n');
        text
    }
}
