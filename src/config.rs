#[derive(Debug, Clone)]
pub struct Config {
    pub path: String,
    pub format: String,
    pub threads: Option<usize>,
    pub exclude: Vec<String>,
    pub custom_patterns: Vec<String>,
    pub quiet: bool,
    pub output: Option<String>,
}

impl Config {
    pub fn new(
        path: String,
        format: String,
        threads: Option<usize>,
        exclude: Vec<String>,
        custom_patterns: Vec<String>,
        quiet: bool,
        output: Option<String>,
    ) -> Self {
        Config {
            path,
            format,
            threads,
            exclude,
            custom_patterns,
            quiet,
            output,
        }
    }
}
