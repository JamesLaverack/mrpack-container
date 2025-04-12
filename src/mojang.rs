use crate::hash_writer;
use digest::Digest;
use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::io;
use std::io::ErrorKind;
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VersionManifest {
    pub id: String,
    pub java_version: JavaVersion,
    pub downloads: Downloads,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JavaVersion {
    pub major_version: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Downloads {
    pub server: Option<Download>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Download {
    #[serde(with = "hex")]
    pub sha1: [u8; 20],
    pub size: u64,
    pub url: Url,
}

#[derive(thiserror::Error, Debug)]
pub enum ApiError {
    #[error("Failed to make HTTP request to {url}")]
    Http { url: Url, source: reqwest::Error },
    #[error("IO Error while downloading file")]
    Io { source: io::Error },
    #[error("Request did not provide an expected content length")]
    ContentLengthNotProvided {},
    #[error("Declared content length too long: {content_length}")]
    ContentLengthTooLong { content_length: u64 },
    #[error("Failed to parse JSON response from API")]
    JsonParse { source: serde_json::Error },
    #[error("Requested Minecraft version {version} not found")]
    VersionNotFound { version: String },
    #[error(
        "Version manifest for version {version} checksum validation failed. Expected {0} but was {1}",
        hex::encode(expected),
        hex::encode(actual)
    )]
    ManifestChecksumFailed {
        version: String,
        expected: [u8; 20],
        actual: [u8; 20],
    },
}

const ROOT_MANIFEST_URL: &str = "https://launchermeta.mojang.com/mc/game/version_manifest_v2.json";

pub async fn download_manifest(minecraft_version: &str) -> Result<VersionManifest, ApiError> {
    let ve = reqwest::get(ROOT_MANIFEST_URL)
        .await
        .map_err(|source| ApiError::Http {
            source,
            url: ROOT_MANIFEST_URL.try_into().unwrap(),
        })?
        .json::<VersionListManifest>()
        .await
        .map_err(|source| ApiError::Http {
            source,
            url: ROOT_MANIFEST_URL.try_into().unwrap(),
        })?
        .versions
        .into_iter()
        .find(|ve| ve.id == minecraft_version)
        .ok_or(ApiError::VersionNotFound {
            version: minecraft_version.to_string(),
        })?;
    let request = reqwest::get(ve.url.clone())
        .await
        .map_err(|source| ApiError::Http {
            source,
            url: ve.url,
        })?;
    let content_length = request
        .content_length()
        .ok_or(ApiError::ContentLengthNotProvided {})?;
    let mut stream = hash_writer::HashReaderAsync::new(
        Sha1::new(),
        tokio_util::io::StreamReader::new(
            request
                .bytes_stream()
                .map_err(|e| io::Error::new(ErrorKind::Other, e)),
        ),
    );

    let mut buf = Vec::with_capacity(
        content_length
            .try_into()
            .map_err(|_| ApiError::ContentLengthTooLong { content_length })?,
    );
    tokio::io::copy(&mut stream, &mut buf)
        .await
        .map_err(|source| ApiError::Io { source })?;
    let (_, checksum) = stream.into_inner().into();
    let checksum_bytes: [u8; 20] = checksum.into();

    if checksum_bytes != ve.sha1 {
        return Err(ApiError::ManifestChecksumFailed {
            expected: ve.sha1,
            actual: checksum.into(),
            version: minecraft_version.to_string(),
        });
    }
    serde_json::from_slice(&buf).map_err(|source| ApiError::JsonParse { source })
}
