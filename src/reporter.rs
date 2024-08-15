use crate::scanner::ScanResult;
use crate::config::Config;
use log::info;
use serde_json;
use std::fs::File;
use std::io::{self, Write};

pub fn report_results(results: &[ScanResult], config: &Config) -> io::Result<()> {
    let output: Box<dyn Write> = if let Some(path) = &config.output {
        Box::new(File::create(path)?)
    } else {
        Box::new(io::stdout())
    };

    match config.format.as_str() {
        "json" => report_json(results, output, config.quiet),
        _ => report_text(results, output, config.quiet),
    }
}

fn report_text(results: &[ScanResult], mut output: Box<dyn Write>, quiet: bool) -> io::Result<()> {
    let vulnerable_results: Vec<_> = results.iter().filter(|r| r.vulnerable).collect();
    let vulnerable_count = vulnerable_results.len();
    
    if !quiet {
        writeln!(output, "Scan Results:")?;
        writeln!(output, "Total files scanned: {}", results.len())?;
        writeln!(output, "Vulnerable files found: {}", vulnerable_count)?;
    }
    
    if vulnerable_count > 0 {
        writeln!(output, "\nVulnerable Files:")?;
        for result in vulnerable_results {
            writeln!(output, "- {}", result.file_path)?;
            writeln!(output, "  Hash: {}", result.file_hash)?;
            if let Some(reason) = &result.reason {
                writeln!(output, "  Reason: {}", reason)?;
            }
            if let Some(severity) = &result.severity {
                writeln!(output, "  Severity: {:?}", severity)?;
            }
            writeln!(output)?;
        }
    }

    Ok(())
}

fn report_json(results: &[ScanResult], mut output: Box<dyn Write>, quiet: bool) -> io::Result<()> {
    let json = if quiet {
        let vulnerable_results: Vec<_> = results.iter().filter(|r| r.vulnerable).collect();
        serde_json::to_string_pretty(&vulnerable_results)
    } else {
        serde_json::to_string_pretty(&results)
    }.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    writeln!(output, "{}", json)?;
    Ok(())
}
