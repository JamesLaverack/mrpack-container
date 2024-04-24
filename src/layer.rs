use crate::hash_writer;
use crate::hash_writer::HashWriterAsync;
use crate::layer::LayerBuilderError::InvalidPath;
use anyhow::Context;
use async_compression::tokio::write::GzipEncoder;
use chrono::DateTime;
use digest::Digest;
use rand::distributions::{Alphanumeric, DistString};
use sha2::Sha256;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

#[derive(thiserror::Error, Debug)]
pub enum LayerBuilderError {
    #[error("Failed to create temporary tar file '{path}' for writing")]
    TmpFileCreation {
        path: PathBuf,
        source: io::Error,
    },
    #[error("Downloaded file '{path}' was an unexpected size. Expected {expected} bytes but was {actual} bytes.")]
    InvalidSize {
        expected: u64,
        actual: u64,
        path: PathBuf,
    },
    #[error("Path '{path}' for tar entry was invalid")]
    InvalidPath {
        path: PathBuf,
        source: io::Error,
    },
    #[error("Failed to write to tar file '{path}'")]
    TmpFileWrite {
        path: PathBuf,
        source: io::Error,
    },
    #[error("Failed to rename tar file from temporary name '{from_path}' to final blob name '{to_path}'")]
    TmpFileRename {
        from_path: PathBuf,
        to_path: PathBuf,
        source: io::Error,
    },
}
pub struct FileInfo {
    pub path: PathBuf,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub last_modified: u64,
}

pub struct TarLayerBuilder {
    blob_dir: PathBuf,
    tmp_tarfile_path: PathBuf,
    writer: GzipEncoder<HashWriterAsync<File, Sha256>>,
}

impl TarLayerBuilder {
    pub async fn new(blob_dir: &Path) -> Result<TarLayerBuilder, LayerBuilderError> {
        let mut filename = ".tmp-".to_owned();
        filename.push_str(&*Alphanumeric.sample_string(&mut rand::thread_rng(), 16));
        filename.push_str(".tar");
        let mut tmp_tarfile_path = blob_dir.clone().to_path_buf();
        tmp_tarfile_path.push(filename);
        let mut gz_writer = GzipEncoder::new(HashWriterAsync::new_sha256(
            File::create(&tmp_tarfile_path).await.map_err(|s| {
                LayerBuilderError::TmpFileCreation {
                    path: tmp_tarfile_path.clone(),
                    source: s,
                }
            })?,
        ));

        return Ok(TarLayerBuilder {
            blob_dir: blob_dir.clone().to_path_buf(),
            tmp_tarfile_path,
            writer: gz_writer,
        });
    }

    pub fn tmp_filepath(&self) -> &Path {
        self.tmp_tarfile_path.as_path()
    }

    pub async fn append_file<R: AsyncRead + std::marker::Unpin>(
        &mut self,
        file_info: &FileInfo,
        file_size: u64,
        mut bytes: R,
    ) -> Result<(), LayerBuilderError> {
        let mut header = tar::Header::new_gnu();
        header
            .set_path(&file_info.path)
            .map_err(|s| LayerBuilderError::InvalidPath {
                path: file_info.path.clone(),
                source: s,
            })?;
        header.set_mode(file_info.mode);
        header.set_uid(file_info.uid);
        header.set_gid(file_info.gid);
        header.set_mtime(file_info.last_modified);
        header.set_size(file_size);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();

        self.writer.write(header.as_bytes()).await.map_err(|s| {
            LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            }
        })?;
        let written = tokio::io::copy(&mut bytes, &mut self.writer).await.map_err(|s| {
            LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            }
        })?;

        if written != file_size {
            // TODO close the file first?
            let _ = tokio::fs::remove_file(&self.tmp_tarfile_path).await;
            return Err(LayerBuilderError::InvalidSize {
                expected: file_size,
                actual: written,
                path: file_info.path.clone(),
            });
        }
        // This segment copied from tar-rs directly
        let buf = [0; 512];
        let remaining = 512 - (written % 512);
        if remaining < 512 {
            self.writer
                .write_all(&buf[..remaining as usize])
                .await
                .map_err(|s| LayerBuilderError::TmpFileWrite {
                    path: self.tmp_tarfile_path.clone(),
                    source: s,
                })?;
        }

        Ok(())
    }

    pub async fn append_symlink(
        &mut self,
        file_info: &FileInfo,
        target: &Path,
    ) -> Result<(), LayerBuilderError> {
        let mut header = tar::Header::new_gnu();
        header
            .set_path(&file_info.path)
            .map_err(|s| LayerBuilderError::InvalidPath {
                path: file_info.path.clone(),
                source: s,
            })?;
        header.set_mode(file_info.mode);
        header.set_uid(file_info.uid);
        header.set_gid(file_info.gid);
        header.set_mtime(file_info.last_modified);
        header.set_entry_type(tar::EntryType::Symlink);
        header
            .set_link_name(target)
            .map_err(|s| LayerBuilderError::InvalidPath {
                path: target.to_path_buf(),
                source: s,
            })?;
        self.writer.write(header.as_bytes()).await.map_err(|s| {
            LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            }
        })?;
        Ok(())
    }

    pub async fn finalise(mut self) -> Result<Layer, LayerBuilderError> {
        // Finalising header
        self.writer
            .write_all(&[0; 1024])
            .await
            .map_err(|s| LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            })?;
        self.writer.shutdown()
            .await
            .map_err(|s| LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            })?;
        let (_, sha256): (File, [u8; 32]) = self.writer.into_inner().into_inner_sha256();
        // Rename it to the checksum
        let mut tarfile_path = self.blob_dir.clone();
        tarfile_path.push(hex::encode(sha256));
        tokio::fs::rename(&self.tmp_tarfile_path, &tarfile_path)
            .await
            .map_err(|s| LayerBuilderError::TmpFileRename {
                from_path: self.tmp_tarfile_path.clone(),
                to_path: tarfile_path.clone(),
                source: s,
            })?;
        Ok(Layer {
            blob_path: tarfile_path,
            sha256_checksum: sha256,
        })
    }
}

pub struct Layer {
    pub blob_path: PathBuf,
    pub sha256_checksum: [u8; 32],
}
