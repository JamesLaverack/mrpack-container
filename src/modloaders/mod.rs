use std::collections::HashMap;
use std::path::PathBuf;

pub mod fabric;
pub mod quilt;

// InContainerMinecraftConfig instructs the mod loader on what the expected configuration of the
// Minecraft container to be. All paths in here are for *inside the container*.
pub struct InContainerMinecraftConfig {
    // The lib directory is where the library JARs for the modloader itself should be placed
    pub lib_dir: PathBuf,
    // The path is where the modloader should be configured to expect the Minecraft JAR
    pub minecraft_jar_path: PathBuf,
    // The working directory is the working dir that Minecraft will be run from. Most mods and mod
    // loaders will expect a particular layout inside of this directory. Typically, they'll also
    // expect it to be writable.
    pub minecraft_working_dir: PathBuf,
}

impl InContainerMinecraftConfig {
    pub fn eula_path(&self) -> PathBuf {
        self.minecraft_working_dir.clone().join("eula.txt")
    }
}

pub struct JavaConfig {
    pub jars: Vec<PathBuf>,
    pub main_class: String,
    pub properties: HashMap<String, String>,
}
