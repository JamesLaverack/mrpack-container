use crate::download;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::fs::File;
use std::path::{Path, PathBuf};
use tracing::*;

pub async fn download_fabric(
    mut path: PathBuf,
    minecraft_version: &str,
    fabric_version: &str,
) -> anyhow::Result<()> {
    // TODO Don't hardcode fabric installer version
    let installer_version = "0.11.1";

    let dl_path = Path::new("https://meta.fabricmc.net/v2/versions/loader")
        .join(minecraft_version)
        .join(fabric_version)
        .join(installer_version)
        .join("server/jar");

    debug!(u = dl_path.to_str(), "Generated jar download URL");
    let layer_res = reqwest::get(dl_path.to_str().unwrap()).await?;
    path.push("server.jar");
    let file = File::create(&path)?;
    let mut hasher = Sha256::new();
    let size = download::stream_to_file_and_hash(layer_res.bytes_stream(), file, &mut hasher).await?;
    info!(
        size_bytes = size,
        sha256 = hasher.result_str(),
        path = path.as_os_str().to_str(),
        installer_version = installer_version,
        minecraft_version = minecraft_version,
        fabric_version = fabric_version,
        "Downloaded fabric server jar"
    );
    Ok(())
}
