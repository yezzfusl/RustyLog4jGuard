use crate::config::Config;
use crate::utils::{is_jar_file, is_class_file};
use log::{debug, info};
use rayon::prelude::*;
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use walkdir::WalkDir;
use zip::ZipArchive;

#[derive(Debug)]
pub struct ScanResult {
    pub file_path: String,
    pub vulnerable: bool,
    pub reason: Option<String>,
}

pub fn scan_directory(config: &Config) -> Result<Vec<ScanResult>, Box<dyn std::error::Error>> {
    info!("Scanning directory: {}", config.path);

    let results: Vec<ScanResult> = WalkDir::new(&config.path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .par_bridge()
        .filter_map(|entry| {
            let path = entry.path();
            if is_jar_file(path) {
                scan_jar(path)
            } else if is_class_file(path) {
                scan_class(path)
            } else {
                None
            }
        })
        .collect();

    Ok(results)
}

fn scan_jar(path: &Path) -> Option<ScanResult> {
    debug!("Scanning JAR file: {:?}", path);

    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            debug!("Error opening JAR file: {:?} - {}", path, e);
            return None;
        }
    };

    let mut archive = match ZipArchive::new(file) {
        Ok(archive) => archive,
        Err(e) => {
            debug!("Error reading JAR file: {:?} - {}", path, e);
            return None;
        }
    };

    for i in 0..archive.len() {
        let mut file = match archive.by_index(i) {
            Ok(file) => file,
            Err(e) => {
                debug!("Error reading file in JAR: {:?} - {}", path, e);
                continue;
            }
        };

        if file.name().ends_with(".class") {
            let mut contents = String::new();
            if let Err(e) = file.read_to_string(&mut contents) {
                debug!("Error reading class file in JAR: {:?} - {}", path, e);
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
            debug!("Error opening class file: {:?} - {}", path, e);
            return None;
        }
    };

    let reader = BufReader::new(file);
    let contents: String = reader.lines().filter_map(|line| line.ok()).collect();

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

fn is_vulnerable(contents: &str) -> bool {
    let vulnerable_patterns = [
        r"org/apache/logging/log4j/core/lookup/JndiLookup",
        r"javax/naming/InitialContext",
        r"javax/naming/Context",
        r"${jndi:",
    ];

    vulnerable_patterns.iter().any(|&pattern| {
        let re = Regex::new(pattern).unwrap();
        re.is_match(contents)
    })
}
