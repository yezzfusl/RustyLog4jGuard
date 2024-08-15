mod config;
mod reporter;
mod scanner;
mod utils;

use clap::Parser;
use config::Config;
use log::{error, info};
use scanner::scan_directory;
use std::process;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to scan
    #[arg(short, long)]
    path: String,

    /// Output format (json or text)
    #[arg(short, long, default_value = "text")]
    format: String,

    /// Number of threads to use for scanning (default: number of logical CPUs)
    #[arg(short, long)]
    threads: Option<usize>,

    /// Exclusion patterns (glob syntax)
    #[arg(short, long)]
    exclude: Vec<String>,

    /// Custom vulnerability patterns (regex)
    #[arg(short, long)]
    custom_patterns: Vec<String>,

    /// Quiet mode (only output vulnerable files)
    #[arg(short, long)]
    quiet: bool,

    /// Save results to file
    #[arg(short, long)]
    output: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();
    let config = Config::new(
        cli.path,
        cli.format,
        cli.threads,
        cli.exclude,
        cli.custom_patterns,
        cli.quiet,
        cli.output,
    );

    if !config.quiet {
        info!("Starting CVE-2021-44228 scanner");
    }
    
    match scan_directory(&config) {
        Ok(results) => {
            reporter::report_results(&results, &config)?;
            if !config.quiet {
                info!("Scanning complete");
            }
            Ok(())
        }
        Err(e) => {
            error!("Error during scanning: {}", e);
            process::exit(1);
        }
    }
}
