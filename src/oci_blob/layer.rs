use crate::hash_writer;
use crate::hash_writer::HashWriterAsync;
use async_compression::Level;
use async_compression::tokio::write::GzipEncoder;
use digest::Digest;
use futures_util::TryStreamExt;
use rand::distr::{Alphanumeric, SampleString};
use sha2::Sha256;
use std::io;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tar::Header;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncBufRead, BufReader};
use tracing::debug;
use url::Url;

#[derive(Default)]
pub struct FileInfo {
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub last_modified: u64,
}

fn build_header<P: AsRef<Path>>(
    path: P,
    file_info: &FileInfo,
) -> Result<Header, super::LayerBuilderError> {
    let mut header = tar::Header::new_ustar();
    let relpath = path.as_ref().strip_prefix("/").map_err(|source| {
        super::LayerBuilderError::RelativePath {
            path: path.as_ref().to_path_buf(),
            source,
        }
    })?;
    header
        .set_path(relpath)
        .map_err(|s| super::LayerBuilderError::InvalidPath {
            path: path.as_ref().to_path_buf(),
            source: s,
        })?;
    header.set_mode(file_info.mode);
    header.set_uid(file_info.uid);
    header.set_gid(file_info.gid);
    header.set_mtime(file_info.last_modified);
    Ok(header)
}

pub struct TarLayerBuilder {
    blob_dir: PathBuf,
    tmp_tarfile_path: PathBuf,
    writer: HashWriterAsync<GzipEncoder<HashWriterAsync<File, Sha256>>, Sha256>,
}

impl TarLayerBuilder {
    pub async fn new<P: AsRef<Path>>(
        blob_dir: P,
    ) -> Result<TarLayerBuilder, super::LayerBuilderError> {
        let mut filename = ".tmp-".to_owned();
        filename.push_str(&*Alphanumeric.sample_string(&mut rand::rng(), 16));
        filename.push_str(".tar");
        let tmp_tarfile_path = blob_dir.as_ref().join(filename);
        let writer = HashWriterAsync::new_sha256(GzipEncoder::with_quality(
            HashWriterAsync::new_sha256(File::create(&tmp_tarfile_path).await.map_err(|s| {
                super::LayerBuilderError::TmpFileCreation {
                    path: tmp_tarfile_path.clone(),
                    source: s,
                }
            })?),
            Level::Best,
        ));

        Ok(TarLayerBuilder {
            blob_dir: blob_dir.as_ref().to_path_buf(),
            tmp_tarfile_path,
            writer,
        })
    }

    pub async fn append_file_from_url<D: Digest, P: AsRef<Path>>(
        &mut self,
        path: P,
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
        let stream = hash_writer::HashReaderAsync::new(
            hasher,
            tokio_util::io::StreamReader::new(
                request
                    .bytes_stream()
                    .map_err(|e| io::Error::new(ErrorKind::Other, e)),
            ),
        );
        let mut buf_stream = BufReader::with_capacity(256 * 1024 * 1024, stream);
        self.append_file(path, &file_info, expected_size, &mut buf_stream)
            .await?;
        let (_, output) = buf_stream.into_inner().into_inner();
        Ok(output)
    }

    pub async fn append_directory<P: AsRef<Path>>(
        &mut self,
        path: P,
        file_info: &FileInfo,
    ) -> Result<(), super::LayerBuilderError> {
        let mut header = build_header(&path, file_info)?;
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
            path = &path.as_ref().as_os_str().to_str().unwrap_or_default(),
            gid = file_info.gid,
            uid = file_info.uid,
            mode = format!("{:#o}", &header.mode().unwrap()),
            last_modified_time = file_info.last_modified,
            "Wrote directory to TAR archive",
        );
        Ok(())
    }

    pub async fn append_file<R: AsyncBufRead + std::marker::Unpin, P: AsRef<Path>>(
        &mut self,
        path: P,
        file_info: &FileInfo,
        file_size: u64,
        bytes: &mut R,
    ) -> Result<(), super::LayerBuilderError> {
        // Write the file header
        let mut header = build_header(&path, file_info)?;
        header.set_size(file_size);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        self.writer.write(header.as_bytes()).await.map_err(|s| {
            super::LayerBuilderError::TmpFileWrite {
                path: self.tmp_tarfile_path.clone(),
                source: s,
            }
        })?;

        // Write the file bytes
        let written = tokio::io::copy_buf(bytes, &mut self.writer)
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
                path: path.as_ref().to_path_buf(),
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
            path = &path.as_ref().as_os_str().to_str().unwrap_or_default(),
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

    pub async fn append_symlink<P: AsRef<Path>, Q: AsRef<Path>>(
        &mut self,
        path: P,
        file_info: &FileInfo,
        target: Q,
    ) -> Result<(), super::LayerBuilderError> {
        let mut header = build_header(&path, file_info)?;
        header.set_entry_type(tar::EntryType::Symlink);
        header
            .set_link_name(&target)
            .map_err(|s| super::LayerBuilderError::InvalidPath {
                path: target.as_ref().to_path_buf(),
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
            path = &path.as_ref().as_os_str().to_str().unwrap_or_default(),
            gid = file_info.gid,
            uid = file_info.uid,
            mode = format!("{:#o}", &header.mode().unwrap()),
            last_modified_time = file_info.last_modified,
            target = &target.as_ref().as_os_str().to_str().unwrap_or_default(),
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
        let (inner, diff_id, _) = self.writer.into_inner_sha256();
        let (_, sha256, total_compressed_bytes): (File, [u8; 32], usize) =
            inner.into_inner().into_inner_sha256();
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
            path: tarfile_path,
            compressed_sha256_checksum: sha256,
            uncompressed_sha256_checksum: diff_id,
            media_type: oci_distribution::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string(),
            compressed_size: total_compressed_bytes as u64,
        })
    }
}
