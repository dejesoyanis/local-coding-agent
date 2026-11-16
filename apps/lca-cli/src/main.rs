//! Binary entry point. Buffered commands are assembled in the library.
//! `ask` writes each text delta to stdout as it arrives.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    lca_cli::init_tracing();
    match lca_cli::interpret(std::env::args_os()) {
        lca_cli::Invocation::Buffered(output) => write_buffered(output),
        lca_cli::Invocation::Ask(command) => stream_ask(command),
        lca_cli::Invocation::Patch(command) => confirm_patch(command),
        lca_cli::Invocation::ProposalApprove(command) => approve_proposal(command),
    }
}

fn approve_proposal(command: lca_cli::ProposalApproveCommand) -> ExitCode {
    if !io::stdin().is_terminal() {
        let _ = writeln!(
            io::stderr(),
            "lca: approval requires an interactive console"
        );
        return ExitCode::from(1);
    }
    let code = lca_cli::run_proposal_approve(
        &command,
        &mut io::stdin().lock(),
        &mut io::stdout(),
        &mut io::stderr(),
    );
    ExitCode::from(code)
}

fn confirm_patch(command: lca_cli::PatchCommand) -> ExitCode {
    let code = lca_cli::run_patch_session(
        &command,
        &mut io::stdin().lock(),
        &mut io::stdout(),
        &mut io::stderr(),
    );
    ExitCode::from(code)
}

fn write_buffered(output: lca_cli::CommandOutput) -> ExitCode {
    if write_output(&mut io::stdout(), output.stdout.as_bytes()).is_err() {
        return ExitCode::from(1);
    }
    if write_output(&mut io::stderr(), output.stderr.as_bytes()).is_err() {
        return ExitCode::from(1);
    }
    ExitCode::from(output.exit_code)
}

fn stream_ask(command: lca_cli::AskCommand) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = writeln!(io::stderr(), "lca: failed to start the runtime: {error}");
            return ExitCode::from(1);
        }
    };
    let code = runtime.block_on(lca_cli::run_ask(
        &command,
        &mut io::stdout(),
        &mut io::stderr(),
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
    ));
    ExitCode::from(code)
}

fn write_output(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    writer.write_all(bytes)?;
    writer.flush()
}
