mod config;
mod reporter;
mod scanner;
mod utils;

use clap::Parser;
use config::Config;
use log::info;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to scan
    #[arg(short, long)]
    path: String,

    /// Output format (json or text)
    #[arg(short, long, default_value = "text")]
    format: String,
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();
    let config = Config::new(cli.path, cli.format);

    info!("Starting CVE-2021-44228 scanner");
    // TODO: Implement scanning logic
    info!("Scanning complete");
}
