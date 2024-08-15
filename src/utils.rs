use std::path::Path;

pub fn is_jar_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext.to_str().unwrap_or("").eq_ignore_ascii_case("jar"))
        .unwrap_or(false)
}

pub fn is_class_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext.to_str().unwrap_or("").eq_ignore_ascii_case("class"))
        .unwrap_or(false)
}
