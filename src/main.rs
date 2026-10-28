use anyhow::Result;
use argus::cli::{Cli, Command};
use clap::Parser;

fn main() -> Result<()> {
    #[cfg(windows)]
    {
        // Ensure we are elevated; relaunch with UAC if needed.
        argus::platform::windows::elevation::ensure_elevated()?;
        // Enable virtual terminal processing for Windows Terminal color API.
        let _ = argus::platform::windows::console::enable_vt();
    }

    let cli = Cli::parse();
    match cli.command {
        None => {
            #[cfg(windows)]
            argus::ui::run_tui(cli)?;
            #[cfg(not(windows))]
            {
                eprintln!("argus TUI is only supported on Windows.");
                std::process::exit(1);
            }
        }
        Some(Command::List(args)) => {
            #[cfg(windows)]
            argus::cli::run_list(args)?;
            #[cfg(not(windows))]
            {
                let _ = args;
                eprintln!("argus list is only supported on Windows.");
                std::process::exit(1);
            }
        }
        Some(Command::Kill(args)) => {
            #[cfg(windows)]
            argus::actions::kill::run_cli_kill(args)?;
            #[cfg(not(windows))]
            {
                let _ = args;
                eprintln!("argus kill is only supported on Windows.");
                std::process::exit(1);
            }
        }
        Some(Command::Doctor) => {
            #[cfg(windows)]
            argus::cli::run_doctor()?;
            #[cfg(not(windows))]
            eprintln!("argus doctor is only supported on Windows.");
        }
    }
    Ok(())
}
