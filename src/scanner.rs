use crate::config::Config;
use crate::utils::{is_jar_file, is_class_file, calculate_file_hash};
use glob::Pattern;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, info, warn};
use rayon::prelude::*;
use regex::Regex;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::Arc;
use walkdir::WalkDir;
use zip::ZipArchive;

#[derive(Debug, serde::Serialize)]
pub struct ScanResult {
    pub file_path: String,
    pub vulnerable: bool,
    pub reason: Option<String>,
    pub severity: Option<Severity>,
    pub file_hash: String,
}

#[derive(Debug, serde::Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

pub fn scan_directory(config: &Config) -> Result<Vec<ScanResult>, Box<dyn std::error::Error>> {
    if !config.quiet {
        info!("Scanning directory: {}", config.path);
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.threads.unwrap_or_else(num_cpus::get))
        .build()?;

    let exclude_patterns: Vec<Pattern> = config.exclude.iter()
        .filter_map(|p| Pattern::new(p).ok())
        .collect();

    let custom_patterns: Vec<Regex> = config.custom_patterns.iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect();

    let entries: Vec<_> = WalkDir::new(&config.path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| !is_excluded(e.path(), &exclude_patterns))
        .collect();

    let progress_bar = if !config.quiet {
        Some(Arc::new(ProgressBar::new(entries.len() as u64)))
    } else {
        None
    };

    if let Some(pb) = &progress_bar {
        pb.set_style(ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            .unwrap()
            .progress_chars("##-"));
    }

    let results: Vec<ScanResult> = pool.install(|| {
        entries.par_iter()
            .filter_map(|entry| {
                let pb = progress_bar.as_ref().map(Arc::clone);
                let path = entry.path();
                let result = if is_jar_file(path) {
                    scan_jar(path, &custom_patterns)
                } else if is_class_file(path) {
                    scan_class(path, &custom_patterns)
                } else {
                    None
                };
                if let Some(pb) = pb {
                    pb.inc(1);
                }
                result
            })
            .collect()
    });

    if let Some(pb) = progress_bar {
        pb.finish_with_message("Scan complete");
    }

    Ok(results)
}

fn is_excluded(path: &Path, patterns: &[Pattern]) -> bool {
    patterns.iter().any(|pattern| pattern.matches_path(path))
}

fn scan_jar(path: &Path, custom_patterns: &[Regex]) -> Option<ScanResult> {
    debug!("Scanning JAR file: {:?}", path);

    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            warn!("Error opening JAR file: {:?} - {}", path, e);
            return None;
        }
    };

    let mut archive = match ZipArchive::new(file) {
        Ok(archive) => archive,
        Err(e) => {
            warn!("Error reading JAR file: {:?} - {}", path, e);
            return None;
        }
    };

    for i in 0..archive.len() {
        let mut file = match archive.by_index(i) {
            Ok(file) => file,
            Err(e) => {
                warn!("Error reading file in JAR: {:?} - {}", path, e);
                continue;
            }
        };

        if file.name().ends_with(".class") {
            let mut contents = Vec::new();
            if let Err(e) = file.read_to_end(&mut contents) {
                warn!("Error reading class file in JAR: {:?} - {}", path, e);
                continue;
            }

            if let Some((vulnerable, reason, severity)) = is_vulnerable(&contents, custom_patterns) {
                return Some(ScanResult {
                    file_path: path.to_string_lossy().to_string(),
                    vulnerable,
                    reason: Some(format!("{} in {}", reason, file.name())),
                    severity: Some(severity),
                    file_hash: calculate_file_hash(path),
                });
            }
        }
    }

    None
}

fn scan_class(path: &Path, custom_patterns: &[Regex]) -> Option<ScanResult> {
    debug!("Scanning class file: {:?}", path);

    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            warn!("Error opening class file: {:?} - {}", path, e);
            return None;
        }
    };

    let mut reader = BufReader::new(file);
    let mut contents = Vec::new();
    if let Err(e) = reader.read_to_end(&mut contents) {
        warn!("Error reading class file: {:?} - {}", path, e);
        return None;
    }

    if let Some((vulnerable, reason, severity)) = is_vulnerable(&contents, custom_patterns) {
        Some(ScanResult {
            file_path: path.to_string_lossy().to_string(),
            vulnerable,
            reason: Some(reason),
            severity: Some(severity),
            file_hash: calculate_file_hash(path),
        })
    } else {
        None
    }
}

fn is_vulnerable(contents: &[u8], custom_patterns: &[Regex]) -> Option<(bool, String, Severity)> {
    let vulnerable_patterns = [
        (r"org/apache/logging/log4j/core/lookup/JndiLookup", Severity::Critical),
        (r"javax/naming/InitialContext", Severity::High),
        (r"javax/naming/Context", Severity::High),
        (r"\$\{jndi:", Severity::Critical),
    ];

    for (pattern, severity) in vulnerable_patterns.iter() {
        let re = Regex::new(pattern).unwrap();
        if re.is_match(&String::from_utf8_lossy(contents)) {
            return Some((true, format!("Vulnerable pattern found: {}", pattern), severity.clone()));
        }
    }

    for pattern in custom_patterns {
        if pattern.is_match(&String::from_utf8_lossy(contents)) {
            return Some((true, format!("Custom vulnerability pattern found: {}", pattern), Severity::High));
        }
    }

    None
}
