use crate::layer::{Blob, TarLayerBuilder};
use digest::Digest;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use tracing::*;

use super::JavaConfig;

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
    // TODO make this a url::Url
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

pub async fn build_quilt_layer(
    oci_blob_dir: &Path,
    minecraft_dir: &Path,
    minecraft_version: &str,
    loader_version: &str,
) -> anyhow::Result<(JavaConfig, Blob)> {
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

    info!(
        blob_dir = oci_blob_dir.as_os_str().to_str().unwrap(),
        "Creating Quilt layer"
    );
    let mut quilt_layer = TarLayerBuilder::new(&oci_blob_dir).await?;

    let mut jar_paths = Vec::new();
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
        jar_path.push(&jar_name);

        let digest: [u8; 32] = quilt_layer
            .append_file_from_url(
                &crate::layer::FileInfo {
                    path: jar_path.clone(),
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    last_modified: 0,
                },
                &url::Url::parse(&download_url.to_str().unwrap())?,
                Sha256::new(),
            )
            .await?
            .into();

        info!(
            name = artifact_id,
            group = group_id.join("."),
            version = version,
            url = lib.url,
            sha256 = hex::encode_upper(digest),
            jar_name = jar_name,
            jar_path = jar_path.as_os_str().to_str().unwrap(),
            download_url = download_url.as_os_str().to_str().unwrap(),
            "Library downloaded"
        );

        // We only want to store the *relative* path.
        jar_paths.push(jar_path.strip_prefix(&minecraft_dir)?.to_path_buf());
    }
    let l = quilt_layer.finalise().await?;
    info!(
        quilt_loader_version = &loader_version,
        minecraft_version = &minecraft_version,
        layer_sha256 = hex::encode_upper(l.sha256_checksum),
        digest = l.digest(),
        layer_path = ?l.blob_path,
        "Created Quilt layer"
    );

    Ok((
        JavaConfig {
            jars: jar_paths,
            main_class: "org.quiltmc.loader.impl.launch.server.QuiltServerLauncher".to_string(),
        },
        l,
    ))
}
