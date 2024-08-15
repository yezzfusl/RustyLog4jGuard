use crate::scanner::ScanResult;
use log::info;
use serde_json;
use std::io::{self, Write};

pub fn report_results(results: &[ScanResult], format: &str) -> io::Result<()> {
    match format {
        "json" => report_json(results),
        _ => report_text(results),
    }
}

fn report_text(results: &[ScanResult]) -> io::Result<()> {
    let vulnerable_count = results.iter().filter(|r| r.vulnerable).count();
    
    writeln!(io::stdout(), "Scan Results:")?;
    writeln!(io::stdout(), "Total files scanned: {}", results.len())?;
    writeln!(io::stdout(), "Vulnerable files found: {}", vulnerable_count)?;
    
    if vulnerable_count > 0 {
        writeln!(io::stdout(), "\nVulnerable Files:")?;
        for result in results.iter().filter(|r| r.vulnerable) {
            writeln!(io::stdout(), "- {}", result.file_path)?;
            if let Some(reason) = &result.reason {
                writeln!(io::stdout(), "  Reason: {}", reason)?;
            }
        }
    }

    Ok(())
}

fn report_json(results: &[ScanResult]) -> io::Result<()> {
    let json = serde_json::to_string_pretty(results).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    writeln!(io::stdout(), "{}", json)?;
    Ok(())
}
