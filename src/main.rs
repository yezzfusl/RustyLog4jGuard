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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();
    let config = Config::new(cli.path, cli.format, cli.threads);

    info!("Starting CVE-2021-44228 scanner");
    
    match scan_directory(&config) {
        Ok(results) => {
            reporter::report_results(&results, &config.format)?;
            info!("Scanning complete");
            Ok(())
        }
        Err(e) => {
            error!("Error during scanning: {}", e);
            process::exit(1);
        }
    }
}
