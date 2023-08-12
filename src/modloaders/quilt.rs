use crate::download;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::fs::File;
use std::path::{Path, PathBuf};
use tracing::*;

pub async fn download_quilt(
    mut path: PathBuf,
    installer_version: &str,
) -> anyhow::Result<()> {
    let dl_path = Path::new("https://maven.quiltmc.org/repository/release/org/quiltmc/quilt-installer")
        .join(installer_version)
        .join(format!("quilt-installer-{}.jar", installer_version));

    // TODO support hash verification
    debug!(u = dl_path.to_str(), "Generated jar download URL");
    let layer_res = reqwest::get(dl_path.to_str().unwrap()).await?;
    path.push("quilt-installer.jar");
    let file = File::create(&path)?;
    let mut hasher = Sha256::new();
    let size = download::stream_to_file_and_hash(layer_res.bytes_stream(), file, &mut hasher).await?;
    info!(
        size_bytes = size,
        sha256 = hasher.result_str(),
        path = "quilt-installer.jar",
        installer_version = installer_version,
        "Downloaded Quilt installer JAR file"
    );
    Ok(())
}
