use std::path::PathBuf;
pub mod quilt;

pub struct JavaConfig {
    pub jars: Vec<PathBuf>,
    pub main_class: String,
}
