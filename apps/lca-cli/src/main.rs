//! Binary entry point. Command behavior lives in the library so it can be tested
//! without panicking on a missing Ollama server.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    lca_cli::init_tracing();
    let output = lca_cli::dispatch(std::env::args_os());
    if write_output(&mut io::stdout(), output.stdout.as_bytes()).is_err() {
        return ExitCode::from(1);
    }
    if write_output(&mut io::stderr(), output.stderr.as_bytes()).is_err() {
        return ExitCode::from(1);
    }
    ExitCode::from(output.exit_code)
}

fn write_output(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    writer.write_all(bytes)?;
    writer.flush()
}
