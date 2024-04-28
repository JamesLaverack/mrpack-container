use anyhow::{bail, Context};
use async_compression::tokio::bufread::XzDecoder;
use async_compression::tokio::bufread::{GzipDecoder, LzmaDecoder, ZlibDecoder, ZstdDecoder};
use async_compression::tokio::write::GzipEncoder;
use chrono::prelude::Utc;
use clap::Parser;
use flate2::write::GzEncoder;
use flate2::Compression;
use futures::io::ErrorKind;
use futures::prelude::*;
use futures_util::StreamExt;
use oci_distribution::{
    client::ClientConfig, config::ConfigFile, manifest::OciDescriptor, secrets::RegistryAuth,
    Client, Reference,
};
use packfile::EnvType;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::time::UNIX_EPOCH;
use std::{collections::HashMap, fs};
use std::{collections::HashSet, fs::File};
use tar::{Builder, EntryType};
use tempfile::tempdir;
use thiserror::Error;
use tokio::io::{AsyncReadExt, BufReader};
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber;

mod download;
mod hash_writer;
mod modloaders;
use crate::arch::Architecture;
use crate::layer::{FileInfo, TarLayerBuilder};
use crate::modloaders::JavaConfig;
#[allow(unused_imports)]
use modloaders::{fabric, forge, quilt};

mod adoptium;
mod arch;
mod deb;
mod layer;
mod mojang;
mod packfile;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[arg(help = "Path to the Modrinth Modpack file")]
    mr_pack_file: String,

    #[arg(help = "Output directory")]
    output_dir: String,

    #[arg(long, help = "Container Architecture", default_value = "amd64")]
    arch: String,

    #[arg(long, help = "Fixed Java version")]
    java_version: Option<String>,

    #[arg(long, help = "Write a EULA acceptance file into the container")]
    accept_eula: bool,

    #[arg(
        long,
        help = "Include the Minecraft server JAR. It's important to remember that with this included the Minecraft EULA forbids you from distributing the resulting contianer."
    )]
    include_mojang_property: bool,

    #[arg(long, help = "Skip creating the container, for debug purposes only")]
    skip_container: bool,

    #[arg(long, help = "Debug logging output")]
    debug: bool,
}

#[derive(Error, Debug)]
#[error("image name '{image_name}' invalid")]
pub struct ImageNameParseError {
    image_name: String,
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("got error from registry")]
    ErrorResponse(oci_spec::distribution::ErrorResponse),
    #[error("JSON parse error")]
    ParseError(serde_json::Error),
}

fn extract_overrides<R: std::io::Read + std::io::Seek>(
    zipfile: &mut zip::ZipArchive<R>,
    minecraft_dir: &std::path::Path,
    overrides: &str,
) -> anyhow::Result<()> {
    for i in 0..zipfile.len() {
        let mut file = zipfile.by_index(i)?;
        if let Some(path) = file.enclosed_name() {
            if path.starts_with(overrides) {
                let stripped_path = path.strip_prefix(overrides)?;
                if file.is_file() {
                    let new_filepath = minecraft_dir.join(stripped_path);
                    if let Some(dirpath) = new_filepath.parent() {
                        fs::create_dir_all(&dirpath)?;
                    }
                    let mut new_file = File::create(&new_filepath)?;
                    info!(
                        filename = path.to_str().unwrap(),
                        overrides = overrides,
                        "Unpacked overrides file"
                    );
                    io::copy(&mut file, &mut new_file)?;
                }
            }
        }
    }
    Ok(())
}

const OS: &str = "linux";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(if args.debug {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let arch = match Architecture::parse(&args.arch) {
        Some(a) => a,
        None => bail!("Architecture not supported"),
    };

    info!(
        arch = ?arch,
        "Running mrpack-container");

    let created_timestamp = Utc::now();

    // Load the pack file and extract it
    let path = Path::new(&args.mr_pack_file);
    if !path.exists() {
        anyhow::bail!("File not found");
    }
    // TODO Support reading from HTTPS
    // TODO Support reading from S3
    // TODO Support reading from Modrinth with modrinth:// or something?
    // TODO Support streaming this, instead of requiring the whole file in one?
    let mut zipfile = zip::ZipArchive::new(File::open(path)?)?;
    let index_file = match zipfile.by_name("modrinth.index.json") {
        Ok(file) => file,
        Err(_) => {
            anyhow::bail!("Failed to find modrinth.index.json file in .mrpack archive");
        }
    };
    let index: packfile::Index = serde_json::from_reader(index_file)?;
    info!(
        path = "file://".to_owned() + &path.as_os_str().to_str().unwrap(),
        name = index.name,
        version = index.version_id,
        "Loaded Modrinth modpack file"
    );

    // Create the output directories
    let oci_archive_dir: PathBuf = args.output_dir.into();
    if oci_archive_dir.exists() {
        warn!(
            path = ?oci_archive_dir,
            "Output directory already exists, some files may be overwritten.")
    }
    let oci_blob_dir = oci_archive_dir.join("blobs").join("sha256");
    fs::create_dir_all(&oci_blob_dir)?;
    info!(
        path = oci_archive_dir.as_os_str().to_str().unwrap(),
        blob_dir = oci_blob_dir.as_os_str().to_str().unwrap(),
        "Assembling new container as oci container"
    );

    // Get a bunch of information about the Minecraft version in-use from Mojang. This uses the
    // Mojang "Piston" API.
    let manifest = mojang::download_manifest(&index.dependencies.minecraft).await?;
    info!(
        minecraft_version = &index.dependencies.minecraft,
        java_major_version = &manifest.java_version.major_version,
        "Retrieved Minecraft version information from Mojang"
    );

    ////////////////////////////////
    //// MUSL
    ////////////////////////////////
    let musl_dep = deb::Package {
        name: "musl".to_string(),
        version: "1.2.5-1".to_string(),
        arch,
    };
    info!(
        deb_version = musl_dep.version,
        url = musl_dep
            .url()
            .map(|u| u.as_str().to_string())
            .unwrap_or("<error>".to_string()),
        "Installing musl"
    );
    let musl_deb_request = reqwest::get(musl_dep.url()?).await?;
    let musl_deb_length = &musl_deb_request.content_length().unwrap();
    let mut musl_tar_stream = tokio_util::io::StreamReader::new(
        musl_deb_request
            .bytes_stream()
            .map_err(|e| io::Error::new(ErrorKind::Other, e)),
    );
    let mut musl_layer = TarLayerBuilder::new(&oci_blob_dir).await?;
    musl_layer
        .append_directory(&layer::FileInfo {
            path: "/lib".into(),
            mode: 0o755,
            uid: 0,
            gid: 0,
            last_modified: 0,
        })
        .await?;
    // TODO This is the worst code I've ever written
    // throw away the first 120 bytes
    debug!("Skipping 120 bytes of file header, debian-binary file, and control.tar.xz header");
    let mut file_header: [u8; 120] = [0; 120];
    (&mut musl_tar_stream)
        .read_exact(&mut file_header)
        .await
        .context("Reading DEB file header from stream")?;

    let mut control_file_size_bytes: [u8; 10] = [0; 10];
    (&mut musl_tar_stream)
        .read_exact(&mut control_file_size_bytes)
        .await
        .context("Reading control file size")?;
    let mut control_file_size_string = std::str::from_utf8(&control_file_size_bytes)
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
    tokio::io::copy(&mut (&mut musl_tar_stream).take(2), &mut tokio::io::sink()).await?;
    // Start of the control.tar.xz file data
    debug!(
        size = control_file_size,
        "skipping control.tar.xz file data bytes"
    );
    tokio::io::copy(
        &mut (&mut musl_tar_stream).take(control_file_size),
        &mut tokio::io::sink(),
    )
    .await?;
    debug!("skipping 48 bytes of data.tar.zx header");
    // skip through the start of the data.tar.zx file header to the size
    tokio::io::copy(&mut (&mut musl_tar_stream).take(48), &mut tokio::io::sink()).await?;
    let mut data_file_size_bytes: [u8; 10] = [0; 10];
    (&mut musl_tar_stream)
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
    tokio::io::copy(&mut (&mut musl_tar_stream).take(2), &mut tokio::io::sink()).await?;
    debug!("Opening xz data stream");
    // data.tar.xz data stream
    let mut compressed_musl_data_stream = &mut (&mut musl_tar_stream).take(data_file_size);
    let mut buffered_compressed_musl_data_stream = BufReader::new(compressed_musl_data_stream);
    let mut musl_data_stream = XzDecoder::new(&mut buffered_compressed_musl_data_stream);
    loop {
        let mut header_bytes: [u8; 512] = [0; 512];
        (&mut musl_data_stream)
            .read_exact(&mut header_bytes)
            .await?;
        if header_bytes == [0; 512] {
            debug!("Read 512 nil bytes, end of stream");
            break;
        }
        let header = tar::Header::from_byte_slice(&header_bytes);
        let size = header.size().context("Header had invalid size")?;
        let path = header.path().context("Header had invalid path")?;
        let entry_type = header.entry_type();
        debug!(
            size = size,
            path = path.as_os_str().to_str(),
            "Parsed data.tar.xz TAR header"
        );
        if entry_type == EntryType::Regular
            && (path.ends_with("libc.so") || path.starts_with(Path::new("./usr/share/doc/")))
        {
            if path.ends_with("libc.so") {
                debug!(
                            path = ?path,
                            "Found shared library");
                musl_layer
                    .append_file(
                        &layer::FileInfo {
                            path: format!("/lib/ld-musl-{}.so.1", arch.linux()).into(),
                            mode: 0o0644,
                            uid: 0,
                            gid: 0,
                            last_modified: 0,
                        },
                        size,
                        &mut (&mut musl_data_stream).take(size),
                    )
                    .await?;
            } else {
                debug!(
                            path = ?path,
                            "Found documentation");
                let mut container_path = Path::new("/").to_path_buf();
                container_path.push(path.to_path_buf().to_path_buf());
                musl_layer
                    .append_file(
                        &layer::FileInfo {
                            path: container_path,
                            mode: 0o0644,
                            uid: 0,
                            gid: 0,
                            last_modified: 0,
                        },
                        size,
                        &mut (&mut musl_data_stream).take(size),
                    )
                    .await?;
            }
            let remaining = 512 - (size % 512) as usize;
            if remaining < 512 {
                let mut padding_bytes: [u8; 512] = [0; 512];
                (&mut musl_data_stream)
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
        } else {
            debug!("Skipping data.tar.xz entry {:?}", path);
            let mut block_bytes: [u8; 512] = [0; 512];
            let expected_blocks = (size / 512) + (if size % 512 == 0 { 0 } else { 1 });
            for _ in 0..expected_blocks {
                (&mut musl_data_stream)
                    .read_exact(&mut header_bytes)
                    .await?;
            }
        }
    }

    let l = musl_layer.finalise().await?;
    info!(
        path = l.blob_path.as_os_str().to_str().unwrap(),
        checksum = hex::encode(l.sha256_checksum),
        "Created MUSL Layer"
    );

    ////////////////////////////////
    //// JRE
    ////////////////////////////////
    let jre_download = adoptium::get_jre_download(manifest.java_version, arch).await?;
    info!(
        url = jre_download.url.to_string(),
        sha256 = hex::encode_upper(jre_download.sha256),
        "Got JRE download info"
    );

    // Download and stream into a layer
    let request = reqwest::get(jre_download.url).await?;
    let length = &request.content_length().unwrap();
    let mut jre_tar_stream = GzipDecoder::new(tokio_util::io::StreamReader::new(
        request
            .bytes_stream()
            .map_err(|e| io::Error::new(ErrorKind::Other, e)),
    ));
    let container_path = Path::new("/usr/local/java");
    let mut jre_layer = TarLayerBuilder::new(&oci_blob_dir).await?;
    loop {
        trace!("Reading from TAR stream");
        // Read a TAR header
        let mut header_bytes: [u8; 512] = [0; 512];
        (&mut jre_tar_stream).read_exact(&mut header_bytes).await?;
        if header_bytes == [0; 512] {
            debug!("Read 512 nil bytes, end of stream");
            break;
        }
        let header = tar::Header::from_byte_slice(&header_bytes);
        let size = header.size().context("Header had invalid size")?;
        let path = header.path().context("Header had invalid path")?;
        let entry_type = header.entry_type();
        debug!(
            size = size,
            path = path.as_os_str().to_str(),
            "Parsed TAR header"
        );
        let mut p = container_path.to_path_buf();
        p.push(path.iter().skip(1).collect::<PathBuf>());
        match entry_type {
            EntryType::Directory => {
                jre_layer
                    .append_directory(&layer::FileInfo {
                        path: p,
                        mode: 0o755,
                        uid: 0,
                        gid: 0,
                        last_modified: 0,
                    })
                    .await?;
            }
            EntryType::Regular => {
                let file_size = header.size()?;
                let upstream_mode = header.mode()?;
                debug!(
                    upstream = format!("{:#o}", upstream_mode),
                    and = format!("{:#o}", upstream_mode & 0o100),
                    "Upstream mode"
                );
                let mode = if upstream_mode & 0o100 > 0 {
                    // Executable
                    0o0755
                } else {
                    // Not executable
                    0o0644
                };
                jre_layer
                    .append_file(
                        &layer::FileInfo {
                            path: p,
                            mode,
                            uid: 0,
                            gid: 0,
                            last_modified: 0,
                        },
                        file_size,
                        &mut (&mut jre_tar_stream).take(size),
                    )
                    .await?;
                // Read the padding bytes from the stream
                let remaining = 512 - (file_size % 512) as usize;
                if remaining < 512 {
                    let mut padding_bytes: [u8; 512] = [0; 512];
                    (&mut jre_tar_stream)
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
            }
            EntryType::Symlink => {
                let mode = if header.mode()? & 0o100 > 0 {
                    // Executable
                    0o755
                } else {
                    // Not executable
                    0o644
                };
                let mut target = container_path.to_path_buf();
                target.push(
                    header
                        .link_name()?
                        .unwrap()
                        .iter()
                        .skip(1)
                        .collect::<PathBuf>(),
                );
                jre_layer
                    .append_symlink(
                        &layer::FileInfo {
                            path: p,
                            mode,
                            uid: 0,
                            gid: 0,
                            last_modified: 0,
                        },
                        &target,
                    )
                    .await?;
            }
            _ => {
                bail!("Unsupported entry type {:?}", entry_type)
            }
        }
    }
    // Write an extra symlink
    jre_layer
        .append_symlink(
            &layer::FileInfo {
                path: Path::new("/usr/bin/java").to_path_buf(),
                mode: 0o755,
                uid: 0,
                gid: 0,
                last_modified: 0,
            },
            Path::new("/usr/local/java/bin/java"),
        )
        .await?;
    let l = jre_layer.finalise().await?;
    info!(
        path = l.blob_path.as_os_str().to_str().unwrap(),
        checksum = hex::encode(l.sha256_checksum),
        "Created JRE Layer"
    );

    ////////////////////////////////
    //// MOD LOADER
    ////////////////////////////////
    // Install the mod loader
    // The way we need to configure the container later will depend on the mod loader. So we'll get
    // a configuration function back
    let java_config;
    if let Some(_fabric_version) = &index.dependencies.fabric_loader {
        anyhow::bail!("fabric not supported");
    } else if let Some(quilt_version) = &index.dependencies.quilt_loader {
        info!(quilt_version = &quilt_version, "Using Quilt modloader");
        java_config = quilt::build_quilt_layer(
            &oci_blob_dir,
            Path::new("/opt/minecraft/"),
            &index.dependencies.minecraft,
            &quilt_version,
        )
        .await?;
    } else if let Some(_forge_version) = &index.dependencies.forge {
        anyhow::bail!("forge not supported");
    } else if let Some(_neoforge_version) = &index.dependencies.neoforge {
        anyhow::bail!("neoforge not supported");
    } else {
        anyhow::bail!("No supported modloader found");
        // TODO support pure vanilla installs?
    }

    ////////////////////////////////
    //// CONTAINER CONFIG
    ////////////////////////////////
    // Write a new config, although much of it will be copied over.
    let mut layer_diff_ids = config_base_file.rootfs.diff_ids.clone();
    //layer_diff_ids.push(format!("sha256:{}", hex::encode(layer_checksum)));
    let config_file = oci_distribution::config::ConfigFile {
        created: Some(created_timestamp),
        architecture: config_base_file.architecture,
        os: config_base_file.os,
        config: Some(oci_distribution::config::Config {
            // TODO force non-root
            user: config_base_file.config.clone().and_then(|c| c.user),
            // The default Minecraft server port
            exposed_ports: Some(HashSet::from(["25565/tcp".to_string()])),
            // TODO fix this clone() mess
            env: config_base_file.config.clone().unwrap_or_default().env,
            cmd: Some(
                [
                    "java".to_string(),
                    // We don't create a custom JAR with everything bundled in, so instead set the classpath to
                    // the individual JAR libraries, and set the main class this way.
                    "--class-path".to_string(),
                    java_config
                        .jars
                        .into_iter()
                        .map(|p| p.as_os_str().to_str().unwrap().to_string())
                        .map(|p| format!("/opt/minecraft/{}", p))
                        .collect::<Vec<String>>()
                        .join(":"),
                    java_config.main_class,
                ]
                .to_vec(),
            ),
            entrypoint: config_base_file.config.unwrap_or_default().entrypoint,
            working_dir: Some("/opt/minecraft".to_string()),
            ..Default::default()
        }),
        // We don't include the history of the base container
        history: Some(vec![oci_distribution::config::History {
            created: Some(created_timestamp),
            author: Some("mrpack-container".to_string()),
            ..Default::default()
        }]),
        rootfs: oci_distribution::config::Rootfs {
            r#type: "layers".to_string(),
            diff_ids: layer_diff_ids,
        },
        ..Default::default()
    };
    // Write out the config JSON file.
    let config_tmp_path = oci_blob_dir.join("config.json");
    let config_tmp_file = File::create(&config_tmp_path)?;
    let mut config_hasher = hash_writer::new(&config_tmp_file, Sha256::new());
    let config_file_json = serde_json::to_string(&config_file)?;
    let config_file_json_bytes = config_file_json.as_bytes();
    config_hasher.write_all(config_file_json_bytes)?;
    config_tmp_file.sync_all()?;
    let config_checksum = config_hasher.finalize_bytes();
    // Rename the `config.json` file to its SHA256 hash checksum.
    let config_hash_name = oci_blob_dir.join(hex::encode(config_checksum));
    fs::rename(config_tmp_path, &config_hash_name)?;
    info!(
        path = config_hash_name.to_str(),
        hash = hex::encode_upper(config_checksum),
        "Wrote Container Config file"
    );
    manifest.config = OciDescriptor {
        media_type: "application/vnd.oci.image.config.v1+json".to_string(),
        digest: format!("sha256:{}", hex::encode(config_checksum)),
        size: i64::try_from(config_file_json_bytes.len())?,
        ..Default::default()
    };

    // Download all the layers
    info!(
        //tmp_dir = format!("{:?}", dir),
        "Downloading container layers"
    );
    // TODO Multithread this, or something
    for layer in &manifest.layers {
        let stream = registry_client
            .pull_blob_stream(&base_image_ref, &layer.digest)
            .await?;
        // TODO don't assume everything is SHA256
        let splits = layer.digest.split(':').collect::<Vec<&str>>();
        let digest = splits.get(1).expect("Layer had no digest hash");
        let layer_path = oci_blob_dir.join(digest);
        let mut hasher = hash_writer::new(File::create(&layer_path)?, Sha256::new());
        download::stream_to_writer(stream, &mut hasher).await?;
        let checksum = hasher.finalize_bytes();
        if hex::encode(checksum) != *digest {
            panic!("Checksum mismatch!")
        }
        info!(
            digest = layer.digest,
            path = layer_path.as_os_str().to_str().unwrap(),
            checksum = hex::encode_upper(checksum),
            size_bytes = layer.size,
            "Downloaded layer"
        );
    }
    manifest.layers = manifest
        .layers
        .into_iter()
        .map(|mut layer| {
            // TODO don't assume all layers are gziped
            layer.media_type = "application/vnd.oci.image.layer.v1.tar+gzip".to_string();
            layer
        })
        .collect();

    // Add our new layer from earlier into the manifest
    manifest.layers.push(OciDescriptor {
        media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_string(),
        //digest: format!("sha256:{}", hex::encode(layer_checksum)),
        size: i64::try_from(config_file_json_bytes.len())?,
        ..Default::default()
    });
    // Set the OCI media type
    manifest.media_type = Some("application/vnd.oci.image.manifest.v1+json".to_string());

    // Write the manifest. In a docker image this is a file in the root named manifest.json
    // in an OCI image it's also a blob.
    let manifest_tmp_file_path = oci_blob_dir.join("manifest.json");
    let manifest_tmp_file = File::create(&manifest_tmp_file_path)?;
    let mut manifest_hasher = hash_writer::new(&manifest_tmp_file, Sha256::new());
    let manifest_string = serde_json::to_string(&manifest)?;
    let manifest_bytes = manifest_string.as_bytes();
    manifest_hasher.write_all(manifest_bytes)?;
    let manifest_checksum = manifest_hasher.finalize_bytes();
    let manifest_hash_name = oci_blob_dir.join(hex::encode(manifest_checksum));
    fs::rename(&manifest_tmp_file_path, &manifest_hash_name)?;
    info!(
        path = manifest_tmp_file_path.as_os_str().to_str().unwrap(),
        len_bytes = manifest_bytes.len(),
        hash = hex::encode_upper(manifest_checksum),
        os = OS,
        arch = args.arch,
        "Wrote image manifest"
    );

    // In an OCI iamge we also require a top-level index.json and oci-layout file.
    let index = oci_distribution::manifest::OciImageIndex {
        schema_version: 2,
        media_type: Some("application/vnd.oci.image.index.v1+json".to_string()),
        manifests: vec![oci_distribution::manifest::ImageIndexEntry {
            media_type: manifest.media_type.unwrap(),
            size: manifest_bytes.len() as i64,
            digest: format!("sha256:{}", hex::encode(manifest_checksum)),
            platform: Some(oci_distribution::manifest::Platform {
                architecture: args.arch,
                os: OS.to_string(),
                os_version: None,
                os_features: None,
                variant: None,
                features: None,
            }),
            annotations: None,
        }],
        annotations: Some(HashMap::from([
            ("org.opencontainers.image.ref.name".to_string(), index.name),
            (
                "org.opencontainers.image.base.name".to_string(),
                base_image_ref.to_string(),
            ),
        ])),
    };
    let index_string = serde_json::to_string(&index)?;
    let index_bytes = index_string.as_bytes();
    let index_file_path = oci_archive_dir.join("index.json");
    let mut index_file = File::create(&index_file_path)?;
    index_file.write_all(index_bytes)?;
    info!(
        path = index_file_path.as_os_str().to_str().unwrap(),
        len_bytes = index_bytes.len(),
        "Wrote OCI Index file"
    );

    let layout_bytes = "{\"imageLayoutVersion\": \"1.0.0\"}".as_bytes();
    let layout_file_path = oci_archive_dir.join("oci-layout");
    let mut layout_file = File::create(&layout_file_path)?;
    layout_file.write_all(layout_bytes)?;
    info!(
        path = layout_file_path.as_os_str().to_str().unwrap(),
        len_bytes = layout_bytes.len(),
        "Wrote OCI layout file"
    );

    // Tar up the completed container image
    /*
    if let Some(of) = &args.output_file {
        let output_tar_file = File::create(of)?;
        let mut tar = Builder::new(output_tar_file);
        tar.append_dir_all("", &oci_archive_dir)?;
        info!(output_file = of, "Outputted saved container TAR");
    }
    if args.stdout {
        let mut tar = Builder::new(io::stdout());
        tar.append_dir_all("", &oci_archive_dir)?;
        info!("Outputted container TAR to STDOUT");
    }
     */

    warn!(
        eula_url = "https://www.minecraft.net/en-us/eula".to_string(),
        "🚨Do NOT distribute this image publicly.🚨 It conatains Mojang property. See the Minecraft EULA.");
    info!("done!");
    Ok(())
}
