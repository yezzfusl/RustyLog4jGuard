use crate::config::Config;
use crate::utils::{is_jar_file, is_class_file, calculate_file_hash};
use blake3::Hasher as Blake3Hasher;
use fftw::array::AlignedVec;
use fftw::plan::*;
use fftw::types::*;
use glob::Pattern;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, info, warn};
use nalgebra::DMatrix;
use num_complex::Complex;
use rayon::prelude::*;
use regex::Regex;
use sha3::{Sha3_256, Digest};
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
    pub sha3_hash: String,
    pub blake3_hash: String,
    pub entropy: f64,
    pub fourier_coefficient: Complex<f64>,
    pub markov_probability: f64,
}

#[derive(Debug, serde::Serialize, Clone)]
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
                return Some(create_scan_result(path, &contents, vulnerable, Some(reason), Some(severity)));
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
        Some(create_scan_result(path, &contents, vulnerable, Some(reason), Some(severity)))
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

fn create_scan_result(path: &Path, contents: &[u8], vulnerable: bool, reason: Option<String>, severity: Option<Severity>) -> ScanResult {
    ScanResult {
        file_path: path.to_string_lossy().to_string(),
        vulnerable,
        reason,
        severity,
        file_hash: calculate_file_hash(path),
        sha3_hash: calculate_sha3_hash(contents),
        blake3_hash: calculate_blake3_hash(contents),
        entropy: calculate_entropy(contents),
        fourier_coefficient: calculate_fourier_coefficient(contents),
        markov_probability: calculate_markov_probability(contents),
    }
}

fn calculate_sha3_hash(contents: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(contents);
    format!("{:x}", hasher.finalize())
}

fn calculate_blake3_hash(contents: &[u8]) -> String {
    let mut hasher = Blake3Hasher::new();
    hasher.update(contents);
    format!("{}", hasher.finalize().to_hex())
}

fn calculate_entropy(contents: &[u8]) -> f64 {
    let mut byte_counts = [0u32; 256];
    for &byte in contents {
        byte_counts[byte as usize] += 1;
    }

    let total_bytes = contents.len() as f64;
    byte_counts.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let prob = count as f64 / total_bytes;
            -prob * prob.log2()
        })
        .sum()
}

fn calculate_fourier_coefficient(contents: &[u8]) -> Complex<f64> {
    let n = contents.len();
    let mut input: AlignedVec<c64> = contents.iter()
        .map(|&x| c64::new(x as f64, 0.0))
        .collect();

    let mut output = AlignedVec::new(n);
    let plan = C2CPlan64::aligned(&[n], Sign::Forward, Flag::MEASURE).unwrap();
    plan.c2c(&mut input, &mut output).unwrap();

    // Return the first non-DC coefficient
    output.get(1).map(|&x| Complex::new(x.re, x.im)).unwrap_or(Complex::new(0.0, 0.0))
}

fn calculate_markov_probability(contents: &[u8]) -> f64 {
    let transition_matrix = calculate_transition_matrix(contents);
    let initial_state = contents[0] as usize;
    
    contents.windows(2)
        .map(|window| transition_matrix[(window[0] as usize, window[1] as usize)])
        .fold(1.0, |acc, prob| acc * prob)
}

fn calculate_transition_matrix(contents: &[u8]) -> DMatrix<f64> {
    let mut counts = DMatrix::zeros(256, 256);
    
    for window in contents.windows(2) {
        let (from, to) = (window[0] as usize, window[1] as usize);
        counts[(from, to)] += 1.0;
    }

    for row in 0..256 {
        let row_sum: f64 = counts.row(row).sum();
        if row_sum > 0.0 {
            for col in 0..256 {
                counts[(row, col)] /= row_sum;
            }
        }
    }

    counts
}
