use super::LayerBuilderError::{JsonError, NotAJsonMediaType};
use crate::hash_writer::HashWriterAsync;
use rand::distributions::{Alphanumeric, DistString};
use serde::Serialize;
use sha2::Sha256;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tracing::debug;

pub struct JsonBlobBuilder {
    blob_dir: PathBuf,
    tmp_tarfile_path: PathBuf,
    writer: HashWriterAsync<File, Sha256>,
    media_type: String,
}

impl JsonBlobBuilder {
    pub async fn new(
        blob_dir: &Path,
        media_type: String,
    ) -> Result<JsonBlobBuilder, super::LayerBuilderError> {
        if !media_type.ends_with("+json") {
            return Err(NotAJsonMediaType { media_type });
        }
        let mut filename = ".tmp-".to_owned();
        filename.push_str(&*Alphanumeric.sample_string(&mut rand::thread_rng(), 16));
        filename.push_str(".json");
        let mut tmp_tarfile_path = blob_dir.to_path_buf();
        tmp_tarfile_path.push(filename);
        let writer = HashWriterAsync::new_sha256(File::create(&tmp_tarfile_path).await.map_err(
            |source| super::LayerBuilderError::TmpFileCreation {
                path: tmp_tarfile_path.clone(),
                source,
            },
        )?);

        return Ok(JsonBlobBuilder {
            blob_dir: blob_dir.to_path_buf(),
            tmp_tarfile_path,
            writer,
            media_type,
        });
    }

    pub async fn append_json<S: Serialize>(
        &mut self,
        data: &S,
    ) -> Result<(), super::LayerBuilderError> {
        let string = serde_json::to_string(data).map_err(|source| JsonError { source })?;
        let bytes = string.as_bytes();
        self.writer.write(&bytes).await.map_err(|source| {
            super::LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source,
            }
        })?;
        debug!(num_bytes = bytes.len(), "Wrote JSON to layer");
        Ok(())
    }

    pub async fn finalise(mut self) -> Result<super::Blob, super::LayerBuilderError> {
        self.writer
            .shutdown()
            .await
            .map_err(|s| super::LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            })?;
        let (_, sha256, total_bytes): (File, [u8; 32], usize) = self.writer.into_inner_sha256();
        // Rename it to the checksum
        let mut tarfile_path = self.blob_dir;
        tarfile_path.push(hex::encode(sha256));
        tokio::fs::rename(&self.tmp_tarfile_path, &tarfile_path)
            .await
            .map_err(|source| super::LayerBuilderError::TmpFileRename {
                from_path: self.tmp_tarfile_path.clone(),
                to_path: tarfile_path.clone(),
                source,
            })?;
        debug!(
            blob_path = tarfile_path.as_os_str().to_str().unwrap(),
            sha256_checksum = hex::encode_upper(sha256),
            "Finished layer"
        );
        Ok(super::Blob {
            path: tarfile_path,
            media_type: self.media_type,
            uncompressed_sha256_checksum: sha256,
            // No compression, so these are the same
            compressed_sha256_checksum: sha256,
            compressed_size: total_bytes as u64,
        })
    }
}
