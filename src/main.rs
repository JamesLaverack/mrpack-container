use anyhow::{bail, Context};
use async_compression::tokio::bufread::GzipDecoder;
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
use tokio::io::AsyncReadExt;
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber;

mod download;
mod hash_writer;
mod modloaders;
use crate::layer::TarLayerBuilder;
use crate::modloaders::JavaConfig;
#[allow(unused_imports)]
use modloaders::{fabric, forge, quilt};

mod adoptium;
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
    info!("Running mrpack-container");

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

    // Ensure the output directory exists
    let oci_archive_dir: PathBuf = args.output_dir.into();
    let oci_blob_dir = oci_archive_dir.join("blobs").join("sha256");
    fs::create_dir_all(&oci_blob_dir)?;
    info!(
        path = oci_archive_dir.as_os_str().to_str().unwrap(),
        blob_dir = oci_blob_dir.as_os_str().to_str().unwrap(),
        "Assembling new container as oci container"
    );

    let manifest = mojang::download_manifest(&index.dependencies.minecraft).await?;
    info!(
        minecraft_version = &index.dependencies.minecraft,
        java_major_version = &manifest.java_version.major_version,
        "Retrieved Minecraft version information from Mojang"
    );
    if args.include_mojang_property {
        match manifest.downloads.server {
            None => anyhow::bail!("Server download unavailable"),
            Some(server_download) => {
                let mut server_jar_layer = TarLayerBuilder::new(&oci_blob_dir).await?;
                debug!(
                    url = &server_download.url.as_str(),
                    sha1 = hex::encode_upper(&server_download.sha1),
                    minecraft_version = &index.dependencies.minecraft,
                    "Downloading Minecraft server JAR..."
                );
                let digest: [u8; 20] = server_jar_layer
                    .append_file_from_url(
                        &layer::FileInfo {
                            path: "server.jar".into(),
                            mode: 0o644,
                            uid: 0,
                            gid: 0,
                            last_modified: 0,
                        },
                        &server_download.url,
                        Sha1::new(),
                    )
                    .await?
                    .into();
                if digest != server_download.sha1 {
                    error!(
                        expected_sha1 = hex::encode_upper(server_download.sha1),
                        actual_sha1 = hex::encode_upper(digest),
                        minecraft_version = &index.dependencies.minecraft,
                        url = server_download.url.as_str(),
                        "server.jar SHA1 checksum did not match!"
                    );
                    anyhow::bail!("Checksum validation failure");
                }
                let l = server_jar_layer.finalise().await?;
                info!(
                    version = &index.dependencies.minecraft,
                    sha1 = hex::encode_upper(digest),
                    url = server_download.url.as_str(),
                    layer_path = l.blob_path.as_os_str().to_str().unwrap(),
                    "Created Minecraft server layer (NOTE: Includes Mojang property)"
                );
            }
        }
    } else {
        info!("Not including Mojang's vanilla server jar. Your modloader will download this at runtime.")
    }

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

    // Get the Vanilla Minecraft server jar
    // Most installs will expect this to be downloaded as server.jar
    /*
    if false {
        let minecraft_vanilla_jar = minecraft_dir.join("server.jar");
        let java_version = mojang::download_server_jar(
            minecraft_vanilla_jar.clone(),
            &index.dependencies.minecraft,
        )
        .await?;

        // Install the mod loader
        // The way we need to configure the container later will depend on the mod loader. So we'll get
        // a configuration function back
        let java_config;
        if let Some(_fabric_version) = &index.dependencies.fabric_loader {
            anyhow::bail!("fabric not supported");
        } else if let Some(quilt_version) = &index.dependencies.quilt_loader {
            java_config = quilt::download_quilt(
                minecraft_dir.into(),
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

        // Install downloads, usually mods
        if let Some(files) = index.files {
            for mrfile in files {
                if let Some(env) = mrfile.env {
                    match env.server {
                        EnvType::Required => {}
                        EnvType::Optional => {
                            info!(path = mrfile.path, "including optional server-side mod");
                        }
                        EnvType::Unsupported => {
                            info!(path = mrfile.path, "skipping unsupported server-side mod");
                            continue;
                        }
                    }
                }
                if mrfile.downloads.len() == 0 {
                    bail!("File had no provided download URLs")
                }
                let u = mrfile.downloads.get(0).unwrap().as_str();
                let request = reqwest::get(u).await?;
                // TODO check for path injection here
                let path = minecraft_dir.join(&mrfile.path);
                fs::create_dir_all(&path.parent().unwrap())?;

                let mut hasher = hash_writer::new(File::create(&path)?, Sha512::new());
                let size = download::stream_to_writer(request.bytes_stream(), &mut hasher).await?;
                let checksum = hasher.finalize_bytes();

                if checksum != mrfile.hashes.sha512 {
                    error!(
                        expected_sha512 = hex::encode_upper(mrfile.hashes.sha512),
                        actual_sha512 = hex::encode_upper(checksum),
                        path = mrfile.path,
                        url = u,
                        "SHA512 checksum did not match!"
                    );
                    bail!("Checksum validation failure");
                }
                info!(
                    size_bytes = size,
                    //sha512 = format!("{:X}", &checksum),
                    path = mrfile.path,
                    url = u,
                    "Downloaded file"
                );
            }
        }
        extract_overrides(&mut zipfile, &minecraft_dir, "overrides")?;
        extract_overrides(&mut zipfile, &minecraft_dir, "server-overrides")?;

        // Write as new layer
        info!("Creating new layer tarball");
        let oci_archive_dir = tempdir()?;
        let oci_blob_dir = oci_archive_dir.join("blobs").join("sha256");
        fs::create_dir_all(&oci_blob_dir)?;
        info!(
            path = oci_archive_dir.as_os_str().to_str().unwrap(),
            "Assembling new container as oci-archive"
        );
    }

     */
    // Grab a JRE
    let jre_download = adoptium::get_jre_download(manifest.java_version, &args.arch).await?;
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

    if args.skip_container {
        warn!("Skipping container creation");
        process::exit(-1);
    }
    let java_config = JavaConfig {
        jars: vec![],
        main_class: "".to_string(),
    };
    /*
        let layer_tmp_path = oci_blob_dir.join("tmp.tar.gz");
        let mut layer_hasher = hash_writer::new(File::create(&layer_tmp_path)?, Sha256::new());
        {
            // Do the TAR creation in a block.
            // This is because as long as this GzEncoder exists, it borrows the hasher. We need
            // that borrow back to do the `.finalize_bytes()` later on.
            let enc = GzEncoder::new(&mut layer_hasher, Compression::best());
            let mut tar = Builder::new(enc);
            // Security feature
            tar.follow_symlinks(false);
            info!("appending to TAR");
            tar.append_dir_all("opt/minecraft", &minecraft_dir)?;
        }
        let layer_checksum = layer_hasher.finalize_bytes();
        // Rename the layer `.tar.gz` file to its SHA256 hash checksum. This is how layers in a OCI
        // image work.
        let layer_hash_name = oci_blob_dir.join(hex::encode(layer_checksum));
        fs::rename(layer_tmp_path, &layer_hash_name)?;
        info!(
            path = layer_hash_name.to_str(),
            hash = hex::encode_upper(layer_checksum),
            "Assembled minecraft layer"
        );
    */
    // Download the rest of the container image layers

    // Clone the os/arch and move them into the closure for lifetime reasons
    let osc = OS.clone();
    let archc = args.arch.clone();
    let client_config = ClientConfig {
        platform_resolver: Some(Box::new(move |manifests| {
            manifests
                .iter()
                .find(|entry| {
                    entry.platform.as_ref().map_or(false, |platform| {
                        platform.os == osc && platform.architecture == archc
                    })
                })
                .map(|e| e.digest.clone())
        })),
        ..Default::default()
    };
    let mut registry_client = Client::new(client_config);
    // We grab a distroless base image. Just glibc, libssl, ca-certs, and a few basics.
    let base_image_ref: Reference = "gcr.io/distroless/static:nonroot".parse()?;
    info!(
        base_image = base_image_ref.whole().as_str(),
        "Determined base container image"
    );

    let (mut manifest, _config_hash, raw_base_config) = registry_client
        .pull_manifest_and_config(&base_image_ref, &RegistryAuth::Anonymous)
        .await?;

    let config_base_file: ConfigFile = serde_json::from_str(&raw_base_config)?;
    info!("Loaded base container config");

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
