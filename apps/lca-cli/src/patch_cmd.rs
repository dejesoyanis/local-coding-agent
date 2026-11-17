//! `lca patch` reviews one stored proposal.
//!
//! `approve` prints the reviewed diff and then reads one line. It does not call a model.
//! There is no flag that supplies the line or skips it. The binary refuses a non-interactive
//! stdin before this function runs.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use lca_config::load_from_path;
use lca_tools::{
    ProposalInspection, ProposalStore, ProposalSummary, ProposalView, RestorationSummary,
    RestorationView,
};

use crate::CommandOutput;
use crate::tools_cmd::{limits_from, sandbox_from};

/// Arguments for `lca patch approve`. The confirmation line is not an argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalApproveCommand {
    /// Configuration file selected by `--config`, or `lca.toml`.
    pub config: PathBuf,
    /// Proposal UUID typed by the operator.
    pub id: String,
}

/// Arguments for `lca patch restoration approve`. The confirmation line is not an argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorationApproveCommand {
    /// Configuration file selected by `--config`, or `lca.toml`.
    pub config: PathBuf,
    /// Restoration UUID typed by the operator.
    pub id: String,
}

pub(crate) fn run_list(config: &Path) -> CommandOutput {
    match open_store(config) {
        Ok((sandbox, store)) => match store.list(&sandbox) {
            Ok(rows) => CommandOutput {
                exit_code: 0,
                stdout: render_list(&rows),
                stderr: String::new(),
            },
            Err(error) => failure(&error.to_string()),
        },
        Err(output) => output,
    }
}

pub(crate) fn run_show(config: &Path, id: &str) -> CommandOutput {
    match open_store(config) {
        Ok((sandbox, store)) => match store.show(&sandbox, id) {
            Ok(view) => CommandOutput {
                exit_code: 0,
                stdout: render_view(&view),
                stderr: String::new(),
            },
            Err(error) => failure(&error.to_string()),
        },
        Err(output) => output,
    }
}

pub(crate) fn run_status(config: &Path, id: &str) -> CommandOutput {
    match open_store(config) {
        Ok((sandbox, store)) => match store.status(&sandbox, id) {
            Ok(summary) => CommandOutput {
                exit_code: 0,
                stdout: render_summary(&summary),
                stderr: String::new(),
            },
            Err(error) => failure(&error.to_string()),
        },
        Err(output) => output,
    }
}

pub(crate) fn run_reject(config: &Path, id: &str) -> CommandOutput {
    match open_store(config) {
        Ok((sandbox, store)) => match store.reject(&sandbox, id) {
            Ok(summary) => CommandOutput {
                exit_code: 0,
                stdout: render_summary(&summary),
                stderr: String::new(),
            },
            Err(error) => failure(&error.to_string()),
        },
        Err(output) => output,
    }
}

pub(crate) fn run_inspect(config: &Path, id: &str) -> CommandOutput {
    match open_store(config) {
        Ok((sandbox, store)) => match store.inspect(&sandbox, id) {
            Ok(report) => CommandOutput {
                exit_code: 0,
                stdout: render_inspection(&report),
                stderr: String::new(),
            },
            Err(error) => failure(&error.to_string()),
        },
        Err(output) => output,
    }
}

pub(crate) fn run_restoration_prepare(config: &Path, id: &str) -> CommandOutput {
    match open_store(config) {
        Ok((sandbox, store)) => match store.prepare_restoration(&sandbox, id) {
            Ok(summary) => CommandOutput {
                exit_code: 0,
                stdout: render_restoration(&summary),
                stderr: String::new(),
            },
            Err(error) => failure(&error.to_string()),
        },
        Err(output) => output,
    }
}

pub(crate) fn run_restoration_show(config: &Path, id: &str) -> CommandOutput {
    match open_store(config) {
        Ok((sandbox, store)) => match store.show_restoration(&sandbox, id) {
            Ok(view) => CommandOutput {
                exit_code: 0,
                stdout: render_restoration_view(&view),
                stderr: String::new(),
            },
            Err(error) => failure(&error.to_string()),
        },
        Err(output) => output,
    }
}

pub(crate) fn run_restoration_status(config: &Path, id: &str) -> CommandOutput {
    match open_store(config) {
        Ok((sandbox, store)) => match store.status_restoration(&sandbox, id) {
            Ok(summary) => CommandOutput {
                exit_code: 0,
                stdout: render_restoration(&summary),
                stderr: String::new(),
            },
            Err(error) => failure(&error.to_string()),
        },
        Err(output) => output,
    }
}

pub(crate) fn run_restoration_recover(config: &Path, id: &str) -> CommandOutput {
    match open_store(config) {
        Ok((sandbox, store)) => match store.recover_restoration(&sandbox, id) {
            Ok(summary) => CommandOutput {
                exit_code: 0,
                stdout: render_restoration(&summary),
                stderr: String::new(),
            },
            Err(error) => failure(&error.to_string()),
        },
        Err(output) => output,
    }
}

pub(crate) fn run_restoration_reject(config: &Path, id: &str) -> CommandOutput {
    match open_store(config) {
        Ok((sandbox, store)) => match store.reject_restoration(&sandbox, id) {
            Ok(summary) => CommandOutput {
                exit_code: 0,
                stdout: render_restoration(&summary),
                stderr: String::new(),
            },
            Err(error) => failure(&error.to_string()),
        },
        Err(output) => output,
    }
}

pub(crate) fn run_recover(config: &Path, id: &str) -> CommandOutput {
    match open_store(config) {
        Ok((sandbox, store)) => match store.recover(&sandbox, id) {
            Ok(report) => CommandOutput {
                exit_code: 0,
                stdout: render_inspection(&report),
                stderr: String::new(),
            },
            Err(error) => failure(&error.to_string()),
        },
        Err(output) => output,
    }
}

/// Prints the review and applies the proposal only when `stdin` repeats that exact line.
pub fn run_proposal_approve<R, W, E>(
    command: &ProposalApproveCommand,
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8
where
    R: BufRead,
    W: Write,
    E: Write,
{
    let config = match load_from_path(&command.config) {
        Ok(config) => config,
        Err(error) => return fail(stderr, &error.to_string()),
    };
    let sandbox = match sandbox_from(&config) {
        Ok(sandbox) => sandbox,
        Err(error) => return fail(stderr, &error),
    };
    let limits = match limits_from(&config) {
        Ok(limits) => limits,
        Err(error) => return fail(stderr, &error),
    };
    let store = match ProposalStore::user_local() {
        Ok(store) => store,
        Err(error) => return fail(stderr, &error.to_string()),
    };
    let view = match store.show(&sandbox, &command.id) {
        Ok(view) => view,
        Err(error) => return fail(stderr, &error.to_string()),
    };
    if writeln!(stdout, "{}", render_view(&view)).is_err() {
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
    match store.approve(&sandbox, &limits, &command.id, &view.digest, &line) {
        Ok(applied) => {
            let _ = writeln!(stdout, "applied: true");
            let _ = writeln!(stdout, "path: {}", applied.path);
            let _ = writeln!(stdout, "new_hash: {}", applied.new_hash);
            0
        }
        Err(error) => fail(stderr, &error.to_string()),
    }
}

/// Prints the restoration review and writes only when `stdin` repeats that exact line.
pub fn run_restoration_approve<R, W, E>(
    command: &RestorationApproveCommand,
    stdin: &mut R,
    stdout: &mut W,
    stderr: &mut E,
) -> u8
where
    R: BufRead,
    W: Write,
    E: Write,
{
    let config = match load_from_path(&command.config) {
        Ok(config) => config,
        Err(error) => return fail(stderr, &error.to_string()),
    };
    let sandbox = match sandbox_from(&config) {
        Ok(sandbox) => sandbox,
        Err(error) => return fail(stderr, &error),
    };
    let limits = match limits_from(&config) {
        Ok(limits) => limits,
        Err(error) => return fail(stderr, &error),
    };
    let store = match ProposalStore::user_local() {
        Ok(store) => store,
        Err(error) => return fail(stderr, &error.to_string()),
    };
    let view = match store.show_restoration(&sandbox, &command.id) {
        Ok(view) => view,
        Err(error) => return fail(stderr, &error.to_string()),
    };
    if writeln!(stdout, "{}", render_restoration_view(&view)).is_err() {
        return 1;
    }
    let mut line = String::new();
    if stdin.read_line(&mut line).is_err() {
        return fail(stderr, "failed to read the restoration approval line");
    }
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    match store.approve_restoration(&sandbox, &limits, &command.id, &view.digest, &line) {
        Ok(restored) => {
            let _ = writeln!(stdout, "restored: true");
            let _ = writeln!(stdout, "path: {}", restored.path);
            let _ = writeln!(stdout, "restored_hash: {}", restored.new_hash);
            0
        }
        Err(error) => fail(stderr, &error.to_string()),
    }
}

fn open_store(
    config: &Path,
) -> Result<(lca_tools::WorkspaceSandbox, ProposalStore), CommandOutput> {
    let loaded = match load_from_path(config) {
        Ok(config) => config,
        Err(error) => return Err(failure(&error.to_string())),
    };
    let sandbox = match sandbox_from(&loaded) {
        Ok(sandbox) => sandbox,
        Err(error) => return Err(failure(&error)),
    };
    match ProposalStore::user_local() {
        Ok(store) => Ok((sandbox, store)),
        Err(error) => Err(failure(&error.to_string())),
    }
}

fn render_list(rows: &[ProposalSummary]) -> String {
    let mut out = String::new();
    push(&mut out, "proposals", &rows.len().to_string());
    for row in rows {
        out.push('\n');
        out.push_str(&render_summary(row));
    }
    out
}

fn render_inspection(report: &ProposalInspection) -> String {
    let mut out = String::new();
    push(&mut out, "proposal_id", &report.id);
    push(&mut out, "path", &report.path);
    push(&mut out, "proposal_state", &report.stored_state);
    push(&mut out, "observed", &report.observed);
    push(&mut out, "original_hash", &report.original_hash);
    push(&mut out, "proposed_hash", &report.proposed_hash);
    push(&mut out, "current_hash", &report.current_hash);
    push(&mut out, "recorded_file_id", &report.recorded_file_id);
    push(&mut out, "current_file_id", &report.current_file_id);
    push(&mut out, "strategy", &report.strategy);
    push(&mut out, "attempt_id", &report.attempt_id);
    push(&mut out, "evidence_phase", &report.evidence_phase);
    push(&mut out, "stage_complete", &report.stage_complete);
    push(&mut out, "mutation_started", &report.mutation_started);
    push(
        &mut out,
        "publication_complete",
        &report.publication_complete,
    );
    push(&mut out, "verification", &report.verification);
    push(&mut out, "recovery", &report.recovery);
    push(&mut out, "conflict", &report.conflict);
    push(&mut out, "next_step", &report.next_step);
    out
}

fn render_summary(summary: &ProposalSummary) -> String {
    let mut out = String::new();
    push(&mut out, "proposal_id", &summary.id);
    push(&mut out, "path", &summary.path);
    push(&mut out, "proposal_state", &summary.state);
    push(&mut out, "expires_at", &summary.expires_at.to_string());
    push(&mut out, "original_hash", &summary.original_hash);
    push(&mut out, "proposed_hash", &summary.proposed_hash);
    out
}

fn render_restoration(summary: &RestorationSummary) -> String {
    let mut out = String::new();
    push(&mut out, "restoration_id", &summary.id);
    push(&mut out, "source_proposal_id", &summary.source_proposal_id);
    push(&mut out, "path", &summary.path);
    push(&mut out, "restoration_state", &summary.state);
    push(&mut out, "expires_at", &summary.expires_at.to_string());
    push(&mut out, "current_sha256", &summary.current_sha256);
    push(&mut out, "restored_sha256", &summary.restored_sha256);
    push(
        &mut out,
        "original_evidence_sha256",
        &summary.original_evidence_sha256,
    );
    push(&mut out, "file_id", &summary.file_id);
    push(&mut out, "attempt_phase", &summary.attempt_phase);
    out
}

fn render_restoration_view(view: &RestorationView) -> String {
    let mut out = render_restoration(&view.summary);
    push(&mut out, "digest", &view.digest);
    push(&mut out, "source", &view.source);
    push(&mut out, "volume_serial", &view.volume_serial.to_string());
    push(&mut out, "source_attempt_id", &view.source_attempt_id);
    push(&mut out, "target_status", &view.target_status);
    push(&mut out, "live_sha256", &view.live_sha256);
    push(&mut out, "confirmation", &view.confirmation);
    out.push_str("diff:\n");
    out.push_str(&view.diff);
    if !view.diff.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn render_view(view: &ProposalView) -> String {
    let mut out = render_summary(&view.summary);
    push(&mut out, "digest", &view.digest);
    push(&mut out, "volume_serial", &view.volume_serial.to_string());
    push(&mut out, "file_id", &view.file_id);
    push(&mut out, "target_status", &view.target_status);
    push(&mut out, "confirmation", &view.confirmation);
    out.push_str("diff:\n");
    out.push_str(&view.diff);
    if !view.diff.ends_with('\n') {
        out.push('\n');
    }
    out
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
