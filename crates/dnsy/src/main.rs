//! The `dnsy` binary: see [`dnsy::run`].

use std::process::ExitCode;

use clap::Parser as _;

fn main() -> ExitCode {
    let cli = dnsy::cli::Cli::parse();
    let runtime = match dnsy::runtime(&cli) {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("dnsy: starting the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(dnsy::run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dnsy: {e}");
            ExitCode::FAILURE
        }
    }
}
