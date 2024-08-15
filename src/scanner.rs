use crate::config::Config;
use crate::utils::{is_jar_file, is_class_file};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, info, warn};
use rayon::prelude::*;
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::Arc;
use walkdir::WalkDir;
use zip::ZipArchive;

#[derive(Debug, serde::Serialize)]
pub struct ScanResult {
    pub file_path: String,
    pub vulnerable: bool,
    pub reason: Option<String>,
}

pub fn scan_directory(config: &Config) -> Result<Vec<ScanResult>, Box<dyn std::error::Error>> {
    info!("Scanning directory: {}", config.path);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(config.threads.unwrap_or_else(num_cpus::get))
        .build()?;

    let entries: Vec<_> = WalkDir::new(&config.path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();

    let progress_bar = Arc::new(ProgressBar::new(entries.len() as u64));
    progress_bar.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
        .unwrap()
        .progress_chars("##-"));

    let results: Vec<ScanResult> = pool.install(|| {
        entries.par_iter()
            .filter_map(|entry| {
                let pb = Arc::clone(&progress_bar);
                let path = entry.path();
                let result = if is_jar_file(path) {
                    scan_jar(path)
                } else if is_class_file(path) {
                    scan_class(path)
                } else {
                    None
                };
                pb.inc(1);
                result
            })
            .collect()
    });

    progress_bar.finish_with_message("Scan complete");

    Ok(results)
}

fn scan_jar(path: &Path) -> Option<ScanResult> {
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

            if is_vulnerable(&contents) {
                return Some(ScanResult {
                    file_path: path.to_string_lossy().to_string(),
                    vulnerable: true,
                    reason: Some(format!("Vulnerable class found: {}", file.name())),
                });
            }
        }
    }

    None
}

fn scan_class(path: &Path) -> Option<ScanResult> {
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

    if is_vulnerable(&contents) {
        Some(ScanResult {
            file_path: path.to_string_lossy().to_string(),
            vulnerable: true,
            reason: Some("Vulnerable code pattern found".to_string()),
        })
    } else {
        None
    }
}

fn is_vulnerable(contents: &[u8]) -> bool {
    let vulnerable_patterns = [
        r"org/apache/logging/log4j/core/lookup/JndiLookup",
        r"javax/naming/InitialContext",
        r"javax/naming/Context",
        r"\$\{jndi:",
    ];

    vulnerable_patterns.iter().any(|&pattern| {
        let re = Regex::new(pattern).unwrap();
        re.is_match(&String::from_utf8_lossy(contents))
    })
}
