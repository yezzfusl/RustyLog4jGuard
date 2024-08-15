#[derive(Debug, Clone)]
pub struct Config {
    pub path: String,
    pub format: String,
    pub threads: Option<usize>,
}

impl Config {
    pub fn new(path: String, format: String, threads: Option<usize>) -> Self {
        Config { path, format, threads }
    }
}
