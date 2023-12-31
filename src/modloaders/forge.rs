use crate::download;
use digest::Digest;
use sha2::Sha256;
use std::fs::File;
use std::path::{Path, PathBuf};
use tracing::*;

pub async fn download_forge(
    mut path: PathBuf,
    minecraft_version: &str,
    forge_version: &str,
) -> anyhow::Result<()> {
    // https://maven.minecraftforge.net/net/minecraftforge/forge/1.20.1-47.1.41/forge-1.20.1-47.1.41-installer.jar
    let version_string = format!("{}-{}", &minecraft_version, &forge_version);

    let dl_path = Path::new("https://maven.minecraftforge.net/net/minecraftforge/forge/")
        .join(&version_string)
        .join(format!("forge-{}-installer.jar", &version_string));

    // TODO support hash verification
    debug!(u = dl_path.to_str(), "Generated jar download URL");
    let layer_res = reqwest::get(dl_path.to_str().unwrap()).await?;
    path.push("forge-installer.jar");
    let file = File::create(&path)?;
    let mut hasher = Sha256::new();
    let size = download::stream_and_hash(layer_res.bytes_stream(), file, &mut hasher).await?;
    info!(
        size_bytes = size,
        //sha256 = hasher.result_str(),
        path = "forge-installer.jar",
        minecraft_version = minecraft_version,
        forge_version = forge_version,
        "Downloaded Forge installer JAR file"
    );
    Ok(())
}
