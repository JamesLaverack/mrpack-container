use std::collections::HashMap;
use std::path::PathBuf;
pub mod fabric;
pub mod quilt;

pub struct JavaConfig {
    pub jars: Vec<PathBuf>,
    pub main_class: String,
    pub properties: HashMap<String, String>,
}
