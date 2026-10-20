//! The `dnsy` binary: see [`dnsy::run`].

use std::process::ExitCode;

use clap::Parser as _;

#[tokio::main]
async fn main() -> ExitCode {
    match dnsy::run(dnsy::cli::Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("dnsy: {e}");
            ExitCode::FAILURE
        }
    }
}
