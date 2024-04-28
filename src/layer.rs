use crate::hash_writer;
use crate::hash_writer::HashWriterAsync;
use crate::layer::LayerBuilderError::{InvalidPath, JsonError, NotAJsonMediaType};
use anyhow::Context;
use async_compression::tokio::write::GzipEncoder;
use chrono::DateTime;
use digest::Digest;
use futures_util::TryStreamExt;
use oci_distribution::manifest::OciDescriptor;
use oci_spec::image::MediaType;
use rand::distributions::{Alphanumeric, DistString};
use serde::Serialize;
use sha2::Sha256;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::{default, io};
use tokio::fs::File;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tracing::debug;
use url::Url;

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
    RelativePath { path: PathBuf },
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

#[derive(Default)]
pub struct FileInfo {
    pub path: PathBuf,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub last_modified: u64,
}

pub struct FileInfoBuilder {
    file_info: FileInfo,
}

impl FileInfoBuilder {
    pub fn build(path: &Path) -> FileInfoBuilder {
        return FileInfoBuilder {
            file_info: FileInfo {
                path: path.to_path_buf(),
                ..Default::default()
            },
        };
    }
    pub fn root(mut self) -> FileInfoBuilder {
        self.file_info.uid = 0;
        self.file_info.gid = 0;
        return self;
    }

    pub fn read_only(mut self) -> FileInfoBuilder {
        self.file_info.mode &= 0x0644;
        return self;
    }

    pub fn executable(mut self) -> FileInfoBuilder {
        self.file_info.mode &= 0x0111;
        return self;
    }
}

impl Into<FileInfo> for FileInfoBuilder {
    fn into(self) -> FileInfo {
        return self.file_info;
    }
}

pub struct JsonBlobBuilder {
    blob_dir: PathBuf,
    tmp_tarfile_path: PathBuf,
    writer: HashWriterAsync<File, Sha256>,
    media_type: MediaType,
}

impl JsonBlobBuilder {
    pub async fn new(
        blob_dir: &Path,
        media_type: MediaType,
    ) -> Result<JsonBlobBuilder, LayerBuilderError> {
        if !format!("{}", media_type).ends_with("+json") {
            return Err(NotAJsonMediaType { media_type });
        }
        let mut filename = ".tmp-".to_owned();
        filename.push_str(&*Alphanumeric.sample_string(&mut rand::thread_rng(), 16));
        filename.push_str(".json");
        let mut tmp_tarfile_path = blob_dir.clone().to_path_buf();
        tmp_tarfile_path.push(filename);
        let mut gz_writer =
            HashWriterAsync::new_sha256(File::create(&tmp_tarfile_path).await.map_err(|s| {
                LayerBuilderError::TmpFileCreation {
                    path: tmp_tarfile_path.clone(),
                    source: s,
                }
            })?);

        return Ok(crate::layer::JsonBlobBuilder {
            blob_dir: blob_dir.clone().to_path_buf(),
            tmp_tarfile_path,
            writer: gz_writer,
            media_type,
        });
    }

    pub fn tmp_filepath(&self) -> &Path {
        self.tmp_tarfile_path.as_path()
    }

    pub async fn append_json<S: Serialize>(&mut self, data: &S) -> Result<(), LayerBuilderError> {
        let string = serde_json::to_string(data).map_err(|source| JsonError { source })?;
        let bytes = string.as_bytes();
        self.writer
            .write(&bytes)
            .await
            .map_err(|s| LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            })?;
        debug!(num_bytes = bytes.len(), "Wrote JSON to layer");
        Ok(())
    }

    pub async fn finalise(mut self) -> Result<Blob, LayerBuilderError> {
        self.writer
            .shutdown()
            .await
            .map_err(|s| LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            })?;
        let (_, sha256, total_bytes): (File, [u8; 32], usize) = self.writer.into_inner_sha256();
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
        debug!(
            blob_path = tarfile_path.as_os_str().to_str().unwrap(),
            sha256_checksum = hex::encode_upper(sha256),
            "Finished layer"
        );
        Ok(Blob {
            blob_path: tarfile_path,
            sha256_checksum: sha256,
            size: total_bytes as u64,
            media_type: self.media_type,
        })
    }
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

    pub async fn append_file_from_url<D: Digest>(
        &mut self,
        file_info: &FileInfo,
        url: &Url,
        hasher: D,
    ) -> Result<digest::Output<D>, LayerBuilderError> {
        let request =
            reqwest::get(url.clone())
                .await
                .map_err(|s| LayerBuilderError::HttpDownloadError {
                    url: url.clone(),
                    source: s,
                })?;
        let expected_size = request.content_length().unwrap();
        let mut stream = hash_writer::HashReaderAsync::new(
            hasher,
            tokio_util::io::StreamReader::new(
                request
                    .bytes_stream()
                    .map_err(|e| io::Error::new(ErrorKind::Other, e)),
            ),
        );
        self.append_file(&file_info, expected_size, &mut stream)
            .await?;
        let (_, output) = stream.into_inner();
        return Ok(output);
    }

    pub async fn append_directory(
        &mut self,
        file_info: &FileInfo,
    ) -> Result<(), LayerBuilderError> {
        let mut header = tar::Header::new_ustar();
        let path =
            file_info
                .path
                .strip_prefix("/")
                .map_err(|s| LayerBuilderError::RelativePath {
                    path: file_info.path.clone(),
                })?;
        header
            .set_path(path)
            .map_err(|s| LayerBuilderError::InvalidPath {
                path: file_info.path.clone(),
                source: s,
            })?;
        header.set_mode(file_info.mode);
        header.set_uid(file_info.uid);
        header.set_gid(file_info.gid);
        header.set_mtime(file_info.last_modified);
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();

        self.writer.write(header.as_bytes()).await.map_err(|s| {
            LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            }
        })?;
        debug!(
            path = path.as_os_str().to_str().unwrap(),
            gid = file_info.gid,
            uid = file_info.uid,
            mode = format!("{:#o}", &header.mode().unwrap()),
            last_modified_time = file_info.last_modified,
            "Wrote directory to TAR archive",
        );
        Ok(())
    }

    pub async fn append_file<R: AsyncRead + std::marker::Unpin>(
        &mut self,
        file_info: &FileInfo,
        file_size: u64,
        bytes: &mut R,
    ) -> Result<(), LayerBuilderError> {
        if file_size == 0 {
            return Err(LayerBuilderError::EmptyFile {
                path: file_info.path.clone(),
            });
        }
        let path =
            file_info
                .path
                .strip_prefix("/")
                .map_err(|s| LayerBuilderError::RelativePath {
                    path: file_info.path.clone(),
                })?;
        let mut header = tar::Header::new_ustar();
        header
            .set_path(path)
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
        let written = tokio::io::copy(bytes, &mut self.writer)
            .await
            .map_err(|s| LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
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
        let padding = if remaining == 512 { 0 } else { remaining };

        debug!(
            path = path.as_os_str().to_str().unwrap(),
            gid = file_info.gid,
            uid = file_info.uid,
            mode = format!("{:#o}", &header.mode().unwrap()),
            last_modified_time = file_info.last_modified,
            file_size = file_size,
            padding_size = padding,
            total_size = file_size + padding,
            blocks = (file_size + padding) / 512,
            "Wrote file to TAR archive",
        );
        Ok(())
    }

    pub async fn append_symlink(
        &mut self,
        file_info: &FileInfo,
        target: &Path,
    ) -> Result<(), LayerBuilderError> {
        let path =
            file_info
                .path
                .strip_prefix("/")
                .map_err(|s| LayerBuilderError::RelativePath {
                    path: file_info.path.clone(),
                })?;
        let mut header = tar::Header::new_ustar();
        header
            .set_path(path)
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
        header.set_cksum();

        self.writer.write(header.as_bytes()).await.map_err(|s| {
            LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            }
        })?;
        debug!(
            path = path.as_os_str().to_str().unwrap(),
            gid = file_info.gid,
            uid = file_info.uid,
            mode = format!("{:#o}", &header.mode().unwrap()),
            last_modified_time = file_info.last_modified,
            target = target.as_os_str().to_str().unwrap(),
            "Wrote symlink to TAR archive",
        );
        Ok(())
    }

    pub async fn finalise(mut self) -> Result<Blob, LayerBuilderError> {
        // Finalising header
        self.writer
            .write_all(&[0; 1024])
            .await
            .map_err(|s| LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            })?;
        self.writer
            .shutdown()
            .await
            .map_err(|s| LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            })?;
        let (_, sha256, total_bytes): (File, [u8; 32], usize) =
            self.writer.into_inner().into_inner_sha256();
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
        debug!(
            blob_path = tarfile_path.as_os_str().to_str().unwrap(),
            sha256_checksum = hex::encode_upper(sha256),
            "Finished layer"
        );
        Ok(Blob {
            blob_path: tarfile_path,
            sha256_checksum: sha256,
            media_type: MediaType::ImageLayerGzip,
            size: total_bytes as u64,
        })
    }
}

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
