use oci_distribution::manifest::OciDescriptor;
use oci_spec::image::MediaType;
use std::io;
use std::path::{PathBuf, StripPrefixError};

pub mod json;
pub mod layer;

pub struct Blob {
    pub blob_path: PathBuf,
    pub sha256_checksum: [u8; 32],
    pub media_type: MediaType,
    pub size: u64,
}

impl Blob {
    pub fn digest(&self) -> String {
        format!("sha256:{}", hex::encode(self.sha256_checksum))
    }
}

impl From<&Blob> for OciDescriptor {
    fn from(layer: &Blob) -> OciDescriptor {
        OciDescriptor {
            digest: layer.digest(),
            media_type: layer.media_type.to_string(),
            size: layer.size as i64,
            ..Default::default()
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum LayerBuilderError {
    #[error("Failed to create temporary tar file '{path}' for writing")]
    TmpFileCreation { path: PathBuf, source: io::Error },
    #[error("Downloaded file '{path}' was an unexpected size. Expected {expected} bytes but was {actual} bytes.")]
    InvalidSize {
        expected: u64,
        actual: u64,
        path: PathBuf,
    },
    #[error("File cannot be empty")]
    EmptyFile { path: PathBuf },
    #[error("Path '{path}' for tar entry was invalid")]
    InvalidPath { path: PathBuf, source: io::Error },
    #[error("Path '{path}' was not an absolute path")]
    RelativePath {
        path: PathBuf,
        source: StripPrefixError,
    },
    #[error("Failed to write to tar file '{path}'")]
    TmpFileWrite { path: PathBuf, source: io::Error },
    #[error("Failed to rename tar file from temporary name '{from_path}' to final blob name '{to_path}'")]
    TmpFileRename {
        from_path: PathBuf,
        to_path: PathBuf,
        source: io::Error,
    },
    #[error("Failed to download file from {url}")]
    HttpDownloadError {
        url: url::Url,
        source: reqwest::Error,
    },
    #[error("Failed to render Json")]
    JsonError { source: serde_json::Error },
    #[error("The media type {media_type} is not a JSON media type")]
    NotAJsonMediaType { media_type: MediaType },
}
