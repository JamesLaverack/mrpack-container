use crate::arch::Architecture;
use crate::oci_blob::layer::{FileInfo, TarLayerBuilder};
use crate::{BuiltLayer, LayerType};
use anyhow::Context;
use async_compression::tokio::bufread::XzDecoder;
use futures_util::TryStreamExt;
use std::io::ErrorKind;
use std::path::Path;
use tar::EntryType;
use tokio::io::{AsyncReadExt, BufReader};
use tracing::{debug, info, warn};

pub struct Package {
    pub name: String,
    pub arch: Architecture,
    pub version: String,
}

impl Package {
    pub fn url(&self) -> Result<url::Url, url::ParseError> {
        // Special workaround for libc6
        // TODO Don't do this, read the Debian APT Release file instead
        let name = if self.name == "libc6" {
            "glibc"
        } else {
            &self.name
        };
        // Yep. HTTP. Not HTTPS, it's a Debian thing.
        url::Url::parse("http://ftp.debian.org/debian/pool/main/")?
            .join(
                (name
                    .chars()
                    .next()
                    .map(|c| c.to_string())
                    .unwrap_or("".to_string())
                    + "/")
                    .as_ref(),
            )?
            .join((name.to_string() + "/").as_ref())?
            .join(&format!(
                "{}_{}_{}.deb",
                self.name,
                self.version,
                self.arch.debian()
            ))
    }
}

pub async fn install_debian_package<P: AsRef<Path>>(
    oci_blob_dir: P,
    package: Package,
) -> anyhow::Result<BuiltLayer> {
    // TODO verify the checksum of this DEB file
    info!(
        version = package.version,
        name = package.name,
        arch = package.arch.debian(),
        url = package
            .url()
            .map(|u| u.as_str().to_string())
            .unwrap_or("<error>".to_string()),
        "Installing debian package"
    );
    let deb_request = reqwest::get(package.url()?).await?;
    if deb_request.status() != 200 {
        warn!(
            version = package.version,
            name = package.name,
            arch = package.arch.debian(),
            url = package
                .url()
                .map(|u| u.as_str().to_string())
                .unwrap_or("<error>".to_string()),
            status_code = deb_request.status().as_str(),
            "Encountered non-200 status code while attempting to download Debian package"
        );
        anyhow::bail!(format!(
            "Got non-200 status code ({})",
            deb_request.status()
        ))
    }
    let mut deb_tar_stream = tokio_util::io::StreamReader::new(
        deb_request
            .bytes_stream()
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e)),
    );
    let mut deb_layer_builder = TarLayerBuilder::new(&oci_blob_dir).await?;
    // TODO This is the worst code I've ever written
    // throw away the first 120 bytes
    debug!("Skipping 120 bytes of file header, debian-binary file, and control.tar.xz header");
    let mut file_header: [u8; 120] = [0; 120];
    (&mut deb_tar_stream)
        .read_exact(&mut file_header)
        .await
        .context("Reading DEB file header from stream")?;

    let mut control_file_size_bytes: [u8; 10] = [0; 10];
    (&mut deb_tar_stream)
        .read_exact(&mut control_file_size_bytes)
        .await
        .context("Reading control file size")?;
    let control_file_size_string = std::str::from_utf8(&control_file_size_bytes)
        .context("Parse control file size as string")?;
    debug!(s = control_file_size_string, "string");
    let control_file_size = control_file_size_string
        .split(" ")
        .next()
        .ok_or(anyhow::anyhow!("No size in ar header"))?
        .parse::<u64>()
        .context("Parse control file size string as int")?;
    debug!(
        bytes = hex::encode_upper(control_file_size_bytes),
        size = control_file_size,
        "Control file size found"
    );
    // Another 6 bytes to finish the header
    debug!("skipping final 2 bytes of control.tar.xz header");
    tokio::io::copy(&mut (&mut deb_tar_stream).take(2), &mut tokio::io::sink()).await?;
    // Start of the control.tar.xz file data
    debug!(
        size = control_file_size,
        "skipping control.tar.xz file data bytes"
    );
    tokio::io::copy(
        &mut (&mut deb_tar_stream).take(control_file_size),
        &mut tokio::io::sink(),
    )
    .await?;
    debug!("skipping 48 bytes of data.tar.zx header");
    // skip through the start of the data.tar.zx file header to the size
    tokio::io::copy(&mut (&mut deb_tar_stream).take(48), &mut tokio::io::sink()).await?;
    let mut data_file_size_bytes: [u8; 10] = [0; 10];
    (&mut deb_tar_stream)
        .read_exact(&mut data_file_size_bytes)
        .await
        .context("Reading data file size")?;
    debug!(
        bytes = hex::encode_upper(data_file_size_bytes),
        "read data file bytes"
    );
    let data_file_size_string =
        std::str::from_utf8(&data_file_size_bytes).context("Parse data file bytes as string")?;
    let data_file_size = data_file_size_string
        .split(" ")
        .next()
        .ok_or(anyhow::anyhow!("No size in ar header"))?
        .parse::<u64>()
        .context("Parse data file length from string to int")?;
    debug!(
        bytes = hex::encode_upper(data_file_size_bytes),
        size = data_file_size,
        "data file size found"
    );
    // Another 6 bytes to finish the header
    debug!("Skipping final 2 bytes of data.tar.zx header");
    tokio::io::copy(&mut (&mut deb_tar_stream).take(2), &mut tokio::io::sink()).await?;
    debug!("Opening xz data stream");
    // data.tar.xz data stream
    let compressed_data_stream = &mut (&mut deb_tar_stream).take(data_file_size);
    let mut buffered_compressed_data_stream = BufReader::new(compressed_data_stream);
    let mut data_stream = BufReader::new(XzDecoder::new(&mut buffered_compressed_data_stream));
    loop {
        let mut header_bytes: [u8; 512] = [0; 512];
        (&mut data_stream).read_exact(&mut header_bytes).await?;
        if header_bytes == [0; 512] {
            debug!("Read 512 nil bytes, end of stream");
            break;
        }
        let header = tar::Header::from_byte_slice(&header_bytes);
        let size = header.size().context("Header had invalid size")?;
        let path = header.path().context("Header had invalid path")?;
        debug!(
            size = size,
            path = path.as_os_str().to_str(),
            "Parsed data.tar.xz TAR header"
        );
        // Rewrite the path, but otherwise pass on as-is
        let newpath = Path::new("/").join(path.strip_prefix("./")?);
        if header.entry_type() == EntryType::Regular {
            deb_layer_builder
                .append_file(
                    &newpath,
                    &FileInfo {
                        mode: 0o0755,
                        uid: 0,
                        gid: 0,
                        last_modified: 0,
                    },
                    size,
                    &mut (&mut data_stream).take(size),
                )
                .await
                .context(format!(
                    "Failed to append file {} (original path {}) from deb {}, arch {}",
                    &newpath.to_str().unwrap_or_default(),
                    path.to_str().unwrap_or_default(),
                    package.name,
                    package.arch.debian()
                ))?;
            let remaining = 512 - (size % 512) as usize;
            if remaining < 512 {
                let mut padding_bytes: [u8; 512] = [0; 512];
                (&mut data_stream)
                    .read_exact(&mut padding_bytes[..remaining])
                    .await?;
                if padding_bytes != [0; 512] {
                    warn!(
                        padding_bytes = remaining,
                        read_bytes = hex::encode_upper(&padding_bytes[..remaining]),
                        "Padding bytes were not nul bytes, maybe corrupt file?"
                    )
                }
            }
        } else if header.entry_type() == EntryType::Symlink {
            deb_layer_builder
                .append_symlink(
                    &newpath,
                    &FileInfo {
                        mode: 0o0755,
                        uid: 0,
                        gid: 0,
                        last_modified: 0,
                    },
                    header.link_name().unwrap().unwrap(),
                )
                .await
                .context(format!(
                    "Failed to apply symlink {} (original path {}) targeting {} from deb {}, arch {}",
                    &newpath.to_str().unwrap_or_default(),
                    path.to_str().unwrap_or_default(),
                    header.link_name().unwrap().unwrap().to_str().unwrap_or_default(),
                    package.name,
                    package.arch.debian()
                ))?;
        } else {
            debug!("Skipping data.tar.xz entry {:?}", path);
            let expected_blocks = (size / 512) + (if size % 512 == 0 { 0 } else { 1 });
            for _ in 0..expected_blocks {
                (&mut data_stream).read_exact(&mut header_bytes).await?;
            }
        }
    }

    let deb_layer = deb_layer_builder.finalise().await?;
    info!(
        path = ?deb_layer.path,
        version = package.version,
        name = package.name,
        arch = package.arch.debian(),
        digest = deb_layer.digest(),
        "Created layer for debian package"
    );
    Ok(BuiltLayer {
        blob: Some(deb_layer),
        layer_type: LayerType::Dependency(package.arch, package.name),
        extra_config: None,
    })
}
