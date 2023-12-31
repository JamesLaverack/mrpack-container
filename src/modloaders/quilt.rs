use crate::download;
use digest::Digest;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::File;
use std::path::PathBuf;
use tracing::*;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ServerLaunchProfile {
    pub id: String,
    pub launcher_main_class: String,
    pub libraries: Vec<Library>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Library {
    pub name: String,
    pub url: String,
}

// split_maven splits a maven artefact
pub fn split_artefact(artefact: &str) -> anyhow::Result<(Vec<&str>, &str, &str)> {
    let splits: Vec<&str> = artefact.split(':').collect();
    if splits.len() != 3 {
        anyhow::bail!("Invalid Maven artefact")
    }
    let group_id: Vec<&str> = splits[0].split('.').collect();
    let artifact_id = splits[1];
    let version = splits[2];
    // Identifiers are lowercase characters, digits, and hyphens. Additionally forbid repeated,
    // leading, or trailing hyphens.
    let identifier = Regex::new(r"^([a-z0-9]+)(-[a-z0-9]+)*$").unwrap();
    for g in &group_id {
        if !identifier.is_match(g) {
            anyhow::bail!("Invalid group identifier")
        }
    }
    if !identifier.is_match(artifact_id) {
        anyhow::bail!("Invalid artifact_id")
    }
    // Version identifiers tend to have seprator symbols like + and - and . in them. We still forbid
    // repeated, trailing, or leading separator symbols.
    let version_identifier = Regex::new(r"^([a-z0-9]+)([-+.][a-z0-9]+)*$").unwrap();
    if !version_identifier.is_match(version) {
        anyhow::bail!("Invalid version")
    }

    return Ok((group_id, artifact_id, version));
}

pub async fn download_quilt(
    minecraft_dir: PathBuf,
    minecraft_version: &str,
    loader_version: &str,
) -> anyhow::Result<()> {
    // We intentionally don't use the Quilt installer. This saves us from either having to bundle
    // Java and run it now, or include it to be run when the container starts, which would take a
    // while.

    // Download the server profile document
    let server_profile_url: PathBuf = [
        "https://meta.quiltmc.org",
        "v3",
        "versions",
        "loader",
        &minecraft_version,
        &loader_version,
        "server",
        "json",
    ]
    .iter()
    .collect();
    let server_profile = reqwest::get(server_profile_url.to_str().unwrap())
        .await?
        .json::<ServerLaunchProfile>()
        .await?;

    let lib_dir = minecraft_dir.join("libraries");

    for lib in server_profile.libraries {
        let (group_id, artifact_id, version) = split_artefact(&lib.name)?;
        // We've already validated these for things like path escapes and other weirdness

        // Determine the JAR name
        let mut jar_name = artifact_id.to_owned();
        jar_name.push_str("-");
        jar_name.push_str(&version);
        jar_name.push_str(".jar");

        // Download URL
        let mut download_url = PathBuf::new();
        download_url.push(&lib.url);
        for g in &group_id {
            download_url.push(g)
        }
        download_url.push(artifact_id);
        download_url.push(version);
        download_url.push(&jar_name);

        // Determine the download path, including the JAR name
        let mut jar_path = lib_dir.clone();
        for g in &group_id {
            jar_path.push(g)
        }
        jar_path.push(artifact_id);
        jar_path.push(version);
        std::fs::create_dir_all(&jar_path)?;
        jar_path.push(&jar_name);
        let jar_file = File::create(&jar_path)?;

        let request = reqwest::get(download_url.to_str().unwrap()).await?;
        let mut hasher = Sha256::new();
        let size = download::stream_and_hash(request.bytes_stream(), jar_file, &mut hasher).await?;
        info!(
            name = artifact_id,
            group = group_id.join("."),
            version = version,
            url = lib.url,
            //sha256 = hasher.result_str(),
            jar_name = jar_name,
            jar_path = jar_path.as_os_str().to_str().unwrap(),
            download_url = download_url.as_os_str().to_str().unwrap(),
            size_bytes = size,
            "Library downloaded"
        );
    }

    // TODO support hash verification
    /*
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
    */
    Ok(())
}
