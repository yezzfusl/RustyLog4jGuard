#[derive(Debug, Clone)]
pub struct Config {
    pub path: String,
    pub format: String,
}

impl Config {
    pub fn new(path: String, format: String) -> Self {
        Config { path, format }
    }
}
