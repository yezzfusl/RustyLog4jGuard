# RustyLog4jGuard
Effortless Log4j vulnerability detection.

## Features

- Recursive scanning of directories for JAR and class files
- Multi-threaded parallel scanning for improved performance
- Identification of potential Log4Shell vulnerabilities
- Support for custom vulnerability patterns using regex
- File and directory exclusion patterns using glob syntax
- Multiple hashing algorithms for file integrity checks:
  - SHA-256
  - SHA-3
  - Blake3
- Advanced analysis techniques:
  - Entropy analysis for detecting obfuscated malicious code
  - Fourier transform analysis for identifying hidden patterns
  - Markov chain analysis for behavioral detection
- Configurable output formats (text and JSON)
- Progress bar for real-time scanning feedback
- Quiet mode for CI/CD integration
- Option to save results to a file

## Prerequisites

- Rust 1.54 or higher
- Cargo (Rust's package manager)

## Installation

1. Clone the repository:

`git clone https://github.com/yezzfusl/RustyLog4jGuard.git`

`cd RustyLog4jGuard`

2. Build the project:

`cargo build --release`

The compiled binary will be available in the `target/release` directory.

## Usage

Run the scanner with the following command:

`./target/release/cve_2021_44228_scanner [OPTIONS] --path <PATH>`

### Options:

- `--path <PATH>`: Specify the directory to scan (required)
- `--format <FORMAT>`: Choose the output format (text or json) [default: text]
- `--threads <THREADS>`: Set the number of threads to use for scanning (optional)
- `--exclude <PATTERN>`: Exclude files/directories matching the given glob pattern (can be used multiple times)
- `--custom-patterns <REGEX>`: Add custom vulnerability patterns as regex (can be used multiple times)
- `--quiet`: Enable quiet mode (only output vulnerable files)
- `--output <FILE>`: Save results to the specified file
- `-h, --help`: Print help information
- `-V, --version`: Print version information


### Examples:

1. Scan a directory with default settings:

`./target/release/cve_2021_44228_scanner --path /path/to/scan`

2. Scan a directory and output results in JSON format:

`./target/release/cve_2021_44228_scanner --path /path/to/scan --format json`

3. Scan a directory using 8 threads:

`./target/release/cve_2021_44228_scanner --path /path/to/scan --threads 8`

## Output

The scanner provides two output formats:

1. Text (default): A human-readable summary of the scan results.
2. JSON: A detailed JSON output of all scan results, suitable for further processing or integration with other tools.

## Performance Considerations

- The scanner uses parallel processing to improve performance on multi-core systems.
- For large directories with many files, increasing the number of threads may improve scanning speed.
- Scanning speed may be limited by I/O performance, especially when dealing with many small files or scanning from a network drive.

## Limitations

- The scanner identifies potential vulnerabilities based on known patterns. It may produce false positives or miss sophisticated obfuscated vulnerabilities.
- Only JAR and class files are scanned. Other file types are ignored.
- The scanner does not decompile or deeply analyze the bytecode, which may limit its ability to detect certain vulnerability variations.

## Contributing

Contributions to improve the scanner are welcome. Please follow these steps:

1. Fork the repository
2. Create a new branch for your feature
3. Commit your changes
4. Push to your branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided as-is for informational and educational purposes only. It should not be considered as a comprehensive security solution. Always consult with cybersecurity professionals and perform thorough testing in controlled environments.

## Acknowledgments

- The Rust community for providing excellent libraries and tools
- The cybersecurity community for their continuous efforts in identifying and mitigating vulnerabilities
