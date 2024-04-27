use crate::download;
use crate::hash_writer;
use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;
use digest::Digest;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::fs::File;
use std::path::PathBuf;
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

pub async fn download_manifest(minecraft_version: &str) -> anyhow::Result<VersionManifest> {
    Ok(
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
                let mut hasher = hash_writer::new((&mut buf).writer(), Sha1::new());
                download::stream_to_writer(request.bytes_stream(), &mut hasher).await?;
                let checksum = hasher.finalize_bytes();
                if checksum != ve.sha1 {
                    error!(
                        expected_sha1 = hex::encode_upper(ve.sha1),
                        actual_sha1 = hex::encode_upper(checksum),
                        minecraft_version = minecraft_version,
                        url = &ve.url.as_str(),
                        "SHA1 for Minecraft version manifest JSON did not match!"
                    );
                    anyhow::bail!("Checksum validation failure");
                }
                serde_json::from_reader((&mut buf).reader())?
            }
        },
    )
}
