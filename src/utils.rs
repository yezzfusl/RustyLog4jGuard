use std::path::Path;
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Read;

/// Check if the given path is a JAR file
pub fn is_jar_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext.to_str().unwrap_or("").eq_ignore_ascii_case("jar"))
        .unwrap_or(false)
}

/// Check if the given path is a class file
pub fn is_class_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext.to_str().unwrap_or("").eq_ignore_ascii_case("class"))
        .unwrap_or(false)
}

/// Calculate SHA256 hash of a file
pub fn calculate_file_hash(path: &Path) -> String {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return String::from("Unable to read file"),
    };

    let mut hasher = Sha256::new();
    let mut buffer = [0; 1024];

    loop {
        let bytes_read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return String::from("Error reading file"),
        };
        hasher.update(&buffer[..bytes_read]);
    }

    format!("{:x}", hasher.finalize())
}
