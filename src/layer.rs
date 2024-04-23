use crate::hash_writer;
use crate::hash_writer::HashWriterAsync;
use async_compression::tokio::write::GzipEncoder;
use chrono::DateTime;
use digest::Digest;
use futures_util::AsyncWriteExt;
use rand::distributions::{Alphanumeric, DistString};
use sha2::Sha256;
use snafu::prelude::*;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncRead;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Snafu)]
enum Error {
    IO(io::Error),
    #[snafu(display("File ({}) was incorrect size. Expected {} from header, but was {}. Tar file is malformed.", path.display(), expected, actual))]
    InvalidSize {
        expected: u64,
        actual: u64,
        path: PathBuf,
    },
}

pub struct TarLayerBuilder {
    blob_dir: PathBuf,
    tmp_tarfile_path: PathBuf,
    files: Vec<TarFileStream>,
}

pub struct FileInfo {
    pub path: PathBuf,
    pub mode: dyn PermissionsExt,
    pub uid: u64,
    pub gid: u64,
    pub last_modified: DateTime<chrono::offset::Utc>,
}

struct TarFileStream {
    header: tar::Header,
    bytes: Option<Box<dyn AsyncRead>>,
    total_size: u64,
}

impl TarLayerBuilder {
    pub fn new(blob_dir: &Path) -> TarLayerBuilder {
        let mut filename = ".tmp-".to_owned();
        filename.push_str(&*Alphanumeric.sample_string(&mut rand::thread_rng(), 16));
        filename.push_str(".tar");
        let mut tmp_tarfile_path = blob_dir.clone().into_path_buf();
        tmp_tarfile_path.push(filename);

        return TarLayerBuilder {
            blob_dir: blob_dir.clone().into_path_buf(),
            tmp_tarfile_path,
            files: vec![],
        };
    }

    pub fn tmp_filepath(&self) -> &Path {
        self.tmp_tarfile_path.as_path()
    }

    pub fn append_file(
        &mut self,
        file_info: &FileInfo,
        file_size: u64,
        bytes: Box<dyn AsyncRead>,
    ) -> Result<(), Error> {
        let mut header = tar::Header::new_gnu();
        header.set_path(&file_info.path)?;
        header.set_mode(file_info.mode.mode());
        header.set_uid(file_info.uid);
        header.set_gid(file_info.gid);
        header.set_mtime(file_info.last_modified.timestamp() as u64);
        header.set_size(file_size);
        header.set_entry_type(tar::EntryType::Regular);
        self.files.push(TarFileStream {
            header,
            total_size: file_size,
            bytes: Some(bytes),
        });
        Ok(())
    }

    pub fn append_symlink(&mut self, file_info: &FileInfo, target: &Path) -> Result<(), Error> {
        let mut header = tar::Header::new_gnu();
        header.set_path(&file_info.path)?;
        header.set_mode(file_info.mode.mode());
        header.set_uid(file_info.uid);
        header.set_gid(file_info.gid);
        header.set_mtime(file_info.last_modified.timestamp() as u64);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name(target)?;
        self.files.push(TarFileStream {
            header,
            total_size: 0,
            bytes: None,
        });
        Ok(())
    }

    pub async fn finalise(mut self) -> Result<Layer, Error> {
        // Tar is sequential, so we have to read things one at a time. In order to make this
        // repeatable we're going to do this strictly in the order entries were added.
        let mut gz_writer = GzipEncoder::new(HashWriterAsync::new::<_, Sha256>(
            File::create(&self.tmp_tarfile_path).await?,
        ));

        // Write each file to the tar format
        for file in self.files.iter_mut() {
            file.header.set_cksum();
            gz_writer.write(file.header.as_bytes()).await?;
            if let Some(reader) = &mut file.bytes {
                let written = tokio::io::copy(&mut *reader, &mut gz_writer);
                if written != file.total_size {
                    // TODO close the file first?
                    tokio::fs::remove_file(&self.tmp_tarfile_path).await?;
                    return Err(Error::InvalidSize {
                        expected: file.total_size,
                        actual: written,
                        path: file.header.path().into(),
                    });
                }
                // This segment copied from tar-rs directly
                let buf = [0; 512];
                let remaining = 512 - (written % 512);
                if remaining < 512 {
                    gz_writer.write_all(&buf[..remaining as usize])?;
                }
            }
        }
        // Finalising header
        gz_writer.write_all([0; 1024]).await?;
        let (mut file, sha256): (File, [u8; 32]) = gz_writer.into_inner().into_inner();
        file.close().await?;

        // Rename it to the checksum
        let mut tarfile_path = self.blob_dir.clone();
        tarfile_path.push(hex::encode(sha256));
        tokio::fs::rename(&self.tmp_tarfile_path, &tarfile_path).await?;
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
