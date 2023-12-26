use crate::download;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::*;
use url::Url;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VersionListManifest {
    pub versions: Vec<VersionListEntry>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VersionListEntry {
    pub id: String,
    pub url: Url,
    #[serde(with = "hex")]
    pub sha1: [u8; 20],
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct VersionManifest {
    pub id: String,
    pub java_version: JavaVersion,
    pub downloads: Downloads,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct JavaVersion {
    pub major_version: u64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Downloads {
    pub server: Option<Download>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Download {
    #[serde(with = "hex")]
    pub sha1: [u8; 20],
    pub size: u64,
    pub url: Url,
}

pub async fn download_server_jar(jar_path: PathBuf, minecraft_version: &str) -> anyhow::Result<()> {
    match reqwest::get("https://launchermeta.mojang.com/mc/game/version_manifest_v2.json")
        .await?
        .json::<VersionListManifest>()
        .await?
        .versions
        .into_iter()
        .find(|ve| ve.id == minecraft_version)
    {
        None => anyhow::bail!("Version not found"),
        Some(ve) => {
            let request = reqwest::get(ve.url.clone()).await?;
            let mut buf = BytesMut::new();
            let mut hasher = Sha1::new();
            download::stream_and_hash(request.bytes_stream(), (&mut buf).writer(), &mut hasher)
                .await?;
            let mut checksum: [u8; 20] = [0; 20];
            hasher.result(&mut checksum);
            if checksum != ve.sha1 {
                error!(
                    expected_sha1 = hex::encode_upper(ve.sha1),
                    actual_sha1 = hex::encode_upper(checksum),
                    url = &ve.url.as_str(),
                    "SHA1 checksum did not match!"
                );
                anyhow::bail!("Checksum validation failure");
            }
            let manifest: VersionManifest = serde_json::from_reader((&mut buf).reader())?;
            match manifest.downloads.server {
                None => anyhow::bail!("Server download unavailable"),
                Some(server_download) => {
                    let request = reqwest::get(server_download.url.clone()).await?;
                    let file = File::create(&jar_path)?;
                    let mut hasher = Sha1::new();
                    download::stream_and_hash(request.bytes_stream(), file, &mut hasher).await?;
                    let mut checksum: [u8; 20] = [0; 20];
                    hasher.result(&mut checksum);
                    if checksum != server_download.sha1 {
                        error!(
                            expected_sha1 = hex::encode_upper(server_download.sha1),
                            actual_sha1 = hex::encode_upper(checksum),
                            url = server_download.url.as_str(),
                            "SHA1 checksum did not match!"
                        );
                        anyhow::bail!("Checksum validation failure");
                    }
                    info!(
                        version = &minecraft_version,
                        sha1 = hex::encode_upper(checksum),
                        url = server_download.url.as_str(),
                        path = jar_path.to_str(),
                        "Downloaded vanilla Minecraft server JAR"
                    );
                    return Ok(());
                }
            }
        }
    }
}
