use crate::hash_writer;
use crate::hash_writer::HashWriterAsync;
use async_compression::tokio::write::GzipEncoder;
use digest::Digest;
use oci_spec::image::MediaType;
use rand::distributions::{Alphanumeric, DistString};
use sha2::Sha256;
use std::io;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use futures_util::TryStreamExt;
use tokio::fs::File;
use tokio::io::AsyncRead;
use tokio::io::AsyncWriteExt;
use tracing::debug;
use url::Url;

#[derive(Default)]
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
    pub async fn new(blob_dir: &Path) -> Result<TarLayerBuilder, super::LayerBuilderError> {
        let mut filename = ".tmp-".to_owned();
        filename.push_str(&*Alphanumeric.sample_string(&mut rand::thread_rng(), 16));
        filename.push_str(".tar");
        let mut tmp_tarfile_path = blob_dir.to_path_buf();
        tmp_tarfile_path.push(filename);
        let writer = GzipEncoder::new(HashWriterAsync::new_sha256(
            File::create(&tmp_tarfile_path).await.map_err(|s| {
                super::LayerBuilderError::TmpFileCreation {
                    path: tmp_tarfile_path.clone(),
                    source: s,
                }
            })?,
        ));

        return Ok(TarLayerBuilder {
            blob_dir: blob_dir.to_path_buf(),
            tmp_tarfile_path,
            writer,
        });
    }

    pub async fn append_file_from_url<D: Digest>(
        &mut self,
        file_info: FileInfo,
        url: &Url,
        hasher: D,
    ) -> Result<digest::Output<D>, super::LayerBuilderError> {
        let request = reqwest::get(url.clone()).await.map_err(|s| {
            super::LayerBuilderError::HttpDownloadError {
                url: url.clone(),
                source: s,
            }
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
    ) -> Result<(), super::LayerBuilderError> {
        let mut header = tar::Header::new_ustar();
        let path = file_info.path.strip_prefix("/").map_err(|source| {
            super::LayerBuilderError::RelativePath {
                path: file_info.path.clone(),
                source,
            }
        })?;
        header
            .set_path(path)
            .map_err(|s| super::LayerBuilderError::InvalidPath {
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
            super::LayerBuilderError::TmpFileWrite {
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
    ) -> Result<(), super::LayerBuilderError> {
        if file_size == 0 {
            return Err(super::LayerBuilderError::EmptyFile {
                path: file_info.path.clone(),
            });
        }
        let path = file_info.path.strip_prefix("/").map_err(|source| {
            super::LayerBuilderError::RelativePath {
                path: file_info.path.clone(),
                source,
            }
        })?;
        let mut header = tar::Header::new_ustar();
        header
            .set_path(path)
            .map_err(|s| super::LayerBuilderError::InvalidPath {
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
            super::LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            }
        })?;
        let written = tokio::io::copy(bytes, &mut self.writer)
            .await
            .map_err(|s| super::LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            })?;

        if written != file_size {
            // TODO close the file first?
            let _ = tokio::fs::remove_file(&self.tmp_tarfile_path).await;
            return Err(super::LayerBuilderError::InvalidSize {
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
                .map_err(|s| super::LayerBuilderError::TmpFileWrite {
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
    ) -> Result<(), super::LayerBuilderError> {
        let path = file_info.path.strip_prefix("/").map_err(|source| {
            super::LayerBuilderError::RelativePath {
                path: file_info.path.clone(),
                source,
            }
        })?;
        let mut header = tar::Header::new_ustar();
        header
            .set_path(path)
            .map_err(|s| super::LayerBuilderError::InvalidPath {
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
            .map_err(|s| super::LayerBuilderError::InvalidPath {
                path: target.to_path_buf(),
                source: s,
            })?;
        header.set_cksum();

        self.writer.write(header.as_bytes()).await.map_err(|s| {
            super::LayerBuilderError::TmpFileWrite {
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

    pub async fn finalise(mut self) -> Result<super::Blob, super::LayerBuilderError> {
        // Finalising header
        self.writer.write_all(&[0; 1024]).await.map_err(|s| {
            super::LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            }
        })?;
        self.writer
            .shutdown()
            .await
            .map_err(|s| super::LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            })?;
        let (_, sha256, total_bytes): (File, [u8; 32], usize) =
            self.writer.into_inner().into_inner_sha256();
        // Rename it to the checksum
        let mut tarfile_path = self.blob_dir;
        tarfile_path.push(hex::encode(sha256));
        tokio::fs::rename(&self.tmp_tarfile_path, &tarfile_path)
            .await
            .map_err(|s| super::LayerBuilderError::TmpFileRename {
                from_path: self.tmp_tarfile_path.clone(),
                to_path: tarfile_path.clone(),
                source: s,
            })?;
        debug!(
            blob_path = tarfile_path.as_os_str().to_str().unwrap(),
            sha256_checksum = hex::encode_upper(sha256),
            "Finished layer"
        );
        Ok(super::Blob {
            blob_path: tarfile_path,
            sha256_checksum: sha256,
            media_type: MediaType::ImageLayerGzip,
            size: total_bytes as u64,
        })
    }
}
