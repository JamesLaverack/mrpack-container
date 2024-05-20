use std::collections::HashMap;
use std::path::PathBuf;

pub mod fabric;
pub mod quilt;

// InContainerMinecraftConfig instructs the mod loader on what the expected configuration of the
// Minecraft container should be.
pub struct InContainerMinecraftConfig {
    // The config directory is the directory that the modloader should be using for configuration,
    // typically the ${minecraft_working_dir}/config. If this is modified, overrides with config
    // files will need to be adjusted too.
    pub config_dir: Option<PathBuf>,
    // The cache directory is used by the modloader for runtime caching. It should be writable.
    pub cache_dir: Option<PathBuf>,
    // The lib directory is where the library JARs for the modloader itself should be placed
    pub lib_dir: PathBuf,
    // The path is where the modloader should be configured to expect the Minecraft JAR
    pub minecraft_jar_path: Option<PathBuf>,
    // The working directory is the working dir that Minecraft will be run with.
    pub minecraft_working_dir: PathBuf,
}

pub struct JavaConfig {
    pub jars: Vec<PathBuf>,
    pub main_class: String,
    pub properties: HashMap<String, String>,
}
