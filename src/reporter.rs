use crate::scanner::ScanResult;
use log::info;
use serde_json;

pub fn report_results(results: &[ScanResult], format: &str) {
    match format {
        "json" => report_json(results),
        _ => report_text(results),
    }
}

fn report_text(results: &[ScanResult]) {
    let vulnerable_count = results.iter().filter(|r| r.vulnerable).count();
    
    println!("Scan Results:");
    println!("Total files scanned: {}", results.len());
    println!("Vulnerable files found: {}", vulnerable_count);
    
    if vulnerable_count > 0 {
        println!("\nVulnerable Files:");
        for result in results.iter().filter(|r| r.vulnerable) {
            println!("- {}", result.file_path);
            if let Some(reason) = &result.reason {
                println!("  Reason: {}", reason);
            }
        }
    }
}

fn report_json(results: &[ScanResult]) {
    let json = serde_json::to_string_pretty(results).unwrap();
    println!("{}", json);
}
