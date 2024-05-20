use std::io::Write;
use std::path::{Path, PathBuf};
use std::{collections::HashMap, fs};
use std::{collections::HashSet, fs::File};

use anyhow::{bail, Context};
use async_compression::tokio::bufread::{GzipDecoder, XzDecoder};
use clap::Parser;
use futures::io::ErrorKind;
use futures::prelude::*;
use oci_distribution::{config::ConfigFile, manifest::OciDescriptor};
use sha2::{Digest, Sha512};
use tar::EntryType;
use tokio::io::{AsyncReadExt, BufReader};
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber;

use modloaders::{fabric, quilt};
use packfile::EnvType;

use crate::arch::Architecture;
use crate::modloaders::InContainerMinecraftConfig;
use crate::oci_blob::{
    json::JsonBlobBuilder,
    layer::{FileInfo, TarLayerBuilder},
    Blob,
};

mod adoptium;
mod arch;
mod deb;
mod hash_writer;
mod modloaders;
mod mojang;
mod oci_blob;
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

    #[arg(long, help = "Debug logging output")]
    debug: bool,
}

async fn extract_overrides_to_layer<R: std::io::Read + std::io::Seek>(
    zipfile: &mut zip::ZipArchive<R>,
    oci_blob_dir: &Path,
    in_container_minecraft_config: &InContainerMinecraftConfig,
    overrides: &str,
) -> anyhow::Result<Option<Blob>> {
    let mut olayer_builder = TarLayerBuilder::new(oci_blob_dir).await?;
    let mut found_overrides = false;
    for i in 0..zipfile.len() {
        let mut file = zipfile.by_index(i)?;
        if let Some(path) = file.enclosed_name().map(|e| e.to_path_buf()) {
            if path.starts_with(overrides) && file.is_file() {
                found_overrides = true;
                // This code is actually awful. We're reading the entire override file into
                // memory. Then streaming it all out. Fine for a few KB of config file. Not fine if
                // someone has a few hundred MB of JAR file in here.
                let mut bytes = Vec::with_capacity(file.size() as usize);
                std::io::copy(&mut file, &mut bytes)?;
                let mrpack_path = path.strip_prefix(overrides)?;
                let mut new_filepath =
                    in_container_minecraft_config.minecraft_working_dir.clone();
                new_filepath.push(mrpack_path);
                olayer_builder
                    .append_file(
                        &FileInfo {
                            path: new_filepath.clone(),
                            mode: if guess_is_writable(&new_filepath) {
                                0o0666
                            } else {
                                0o0644
                            },
                            uid: 0,
                            gid: 0,
                            last_modified: 0,
                        },
                        file.size(),
                        &mut bytes.as_slice(),
                    )
                    .await?;
                info!(
                    path = ?new_filepath,
                    overrides = overrides,
                    "Unpacked overrides file"
                );
            }
        }
    }
    Ok(if found_overrides {
        let layer = olayer_builder.finalise().await?;
        info!(
            path = ?&layer.path,
            digest = &layer.digest(),
            overrides = overrides,
            "Created Overrides Layer"
        );
        Some(layer)
    } else {
        olayer_builder.cancel().await?;
        None
    })
}

// Some files and directories are expected to be writable by various mods. However, the MRPACK
// format does not encode any permission information. Instead, we'll have to guess if it should
// be writable or read-only based on the filename.
fn guess_is_writable(path: &Path) -> bool {
    path.iter().next().map(|p| p == "config").unwrap_or(false)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO break this function out so it's not hundreds of lines long
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

    // Load the pack file and extract it
    let path = Path::new(&args.mr_pack_file);
    if !path.exists() {
        anyhow::bail!("File not found");
    }
    // TODO use Async reading on this file, instead of sync code
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

    let java_version = args
        .java_version
        .unwrap_or(format!("{}", &manifest.java_version.major_version));

    let mut layers: Vec<oci_blob::Blob> = vec![];

    ////////////////////////////////
    //// MUSL
    ////////////////////////////////
    // TODO verify the checksum of this DEB file
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
    let mut musl_tar_stream = tokio_util::io::StreamReader::new(
        musl_deb_request
            .bytes_stream()
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e)),
    );
    let mut musl_layer_builder = TarLayerBuilder::new(&oci_blob_dir).await?;
    musl_layer_builder
        .append_directory(&FileInfo {
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
    let compressed_musl_data_stream = &mut (&mut musl_tar_stream).take(data_file_size);
    let mut buffered_compressed_musl_data_stream = BufReader::new(compressed_musl_data_stream);
    let mut musl_data_stream =
        BufReader::new(XzDecoder::new(&mut buffered_compressed_musl_data_stream));
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
                musl_layer_builder
                    .append_file(
                        &FileInfo {
                            path: format!("/lib/ld-musl-{}.so.1", arch.linux()).into(),
                            mode: 0o0755,
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
                musl_layer_builder
                    .append_file(
                        &FileInfo {
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
            let expected_blocks = (size / 512) + (if size % 512 == 0 { 0 } else { 1 });
            for _ in 0..expected_blocks {
                (&mut musl_data_stream)
                    .read_exact(&mut header_bytes)
                    .await?;
            }
        }
    }

    let musl_layer = musl_layer_builder.finalise().await?;
    info!(
        path = ?musl_layer.path,
        digest = musl_layer.digest(),
        "Created MUSL Layer"
    );
    layers.push(musl_layer);

    ////////////////////////////////
    //// JRE
    ////////////////////////////////
    let jre_download = adoptium::get_jre_download(&java_version, arch).await?;
    info!(
        url = jre_download.url.to_string(),
        sha256 = hex::encode_upper(jre_download.sha256),
        "Got JRE download info"
    );

    // Download and stream into a layer
    let request = reqwest::get(jre_download.url).await?;
    let mut jre_tar_stream = BufReader::new(GzipDecoder::new(tokio_util::io::StreamReader::new(
        request
            .bytes_stream()
            .map_err(|e| std::io::Error::new(ErrorKind::Other, e)),
    )));
    let container_path = Path::new("/usr/local/java");
    let mut jre_layer_builder = TarLayerBuilder::new(&oci_blob_dir).await?;
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
                jre_layer_builder
                    .append_directory(&FileInfo {
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
                jre_layer_builder
                    .append_file(
                        &FileInfo {
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
                jre_layer_builder
                    .append_symlink(
                        &FileInfo {
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
    jre_layer_builder
        .append_symlink(
            &FileInfo {
                path: Path::new("/bin/java").to_path_buf(),
                mode: 0o755,
                uid: 0,
                gid: 0,
                last_modified: 0,
            },
            Path::new("/usr/local/java/bin/java"),
        )
        .await?;
    let jre_layer = jre_layer_builder.finalise().await?;
    info!(
        path = ?jre_layer.path,
        digest = jre_layer.digest(),
        "Created JRE Layer"
    );
    layers.push(jre_layer);

    ////////////////////////////////
    //// MOD LOADER
    ////////////////////////////////
    // Install the mod loader
    // The way we need to configure the container later will depend on the mod loader. So we'll get
    // a configuration function back
    let java_config;
    let modloader_layer;
    let in_container_minecraft_config = modloaders::InContainerMinecraftConfig {
        lib_dir: Path::new("/usr/local/minecraft/lib").to_path_buf(),
        minecraft_jar_path: Path::new("/usr/local/minecraft/server.jar").to_path_buf(),
        minecraft_working_dir: Path::new("/var/minecraft").to_path_buf(),
    };
    if let Some(fabric_version) = &index.dependencies.fabric_loader {
        info!(fabric_version = &fabric_version, "Using Fabric modloader");
        (java_config, modloader_layer) = fabric::build_fabric_layer(
            &oci_blob_dir,
            &in_container_minecraft_config,
            &index.dependencies.minecraft,
            &fabric_version,
        )
        .await?;
    } else if let Some(quilt_version) = &index.dependencies.quilt_loader {
        info!(quilt_version = &quilt_version, "Using Quilt modloader");
        (java_config, modloader_layer) = quilt::build_quilt_layer(
            &oci_blob_dir,
            &in_container_minecraft_config,
            &index.dependencies.minecraft,
            &quilt_version,
        )
        .await?;
    } else if let Some(_forge_version) = &index.dependencies.forge {
        // TODO Support Forge
        anyhow::bail!("forge not yet supported");
    } else if let Some(_neoforge_version) = &index.dependencies.neoforge {
        // TODO Support Neoforge
        anyhow::bail!("neoforge not yet supported");
    } else {
        anyhow::bail!("No modloader found");
    }
    layers.push(modloader_layer);

    ////////////////////////////////
    //// DOWNLAODS
    ////////////////////////////////
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

            let mut container_path = in_container_minecraft_config.minecraft_working_dir.clone();
            container_path.push(mrfile.path);

            let u = mrfile.downloads.get(0).unwrap();
            let mut file_layer_builder = TarLayerBuilder::new(&oci_blob_dir).await?;
            let digest: [u8; 64] = file_layer_builder
                .append_file_from_url(
                    FileInfo {
                        path: container_path.clone(),
                        mode: if guess_is_writable(&container_path) {
                            0o666
                        } else {
                            0o644
                        },
                        uid: 0,
                        gid: 0,
                        last_modified: 0,
                    },
                    &u,
                    Sha512::new(),
                )
                .await?
                .into();
            if digest != mrfile.hashes.sha512 {
                error!(
                    expected_sha512 = hex::encode_upper(mrfile.hashes.sha512),
                    actual_sha512 = hex::encode_upper(digest),
                    container_path = ?&container_path,
                    url = &u.to_string(),
                    "SHA512 checksum did not match!"
                );
                bail!("Checksum validation failure");
            }
            let file_layer = file_layer_builder.finalise().await?;
            info!(
                path = ?&file_layer.path,
                digest = &file_layer.digest(),
                sha512 = hex::encode_upper(digest),
                container_path = ?&container_path,
                url = &u.to_string(),
                "Downloaded file into layer"
            );
            layers.push(file_layer);
        }
    }

    ////////////////////////////////
    //// OVERRIDES
    ////////////////////////////////
    extract_overrides_to_layer(
        &mut zipfile,
        &oci_blob_dir,
        &in_container_minecraft_config,
        "overrides",
    )
    .await?
    .map(|l| layers.push(l));

    extract_overrides_to_layer(
        &mut zipfile,
        &oci_blob_dir,
        &in_container_minecraft_config,
        "server-overrides",
    )
    .await?
    .map(|l| layers.push(l));

    ////////////////////////////////
    //// Directory Permissions
    ////////////////////////////////
    let mut permissions_layer_builder = TarLayerBuilder::new(&oci_blob_dir).await?;
    // Set permissions on some directories
    permissions_layer_builder
        .append_directory(&FileInfo {
            path: Path::new("/tmp").to_path_buf(),
            // World writable
            mode: 0o777,
            uid: 0,
            gid: 0,
            last_modified: 0,
        })
        .await?;
    permissions_layer_builder
        .append_directory(&FileInfo {
            path: Path::new("/var").to_path_buf(),
            mode: 0o755,
            uid: 0,
            gid: 0,
            last_modified: 0,
        })
        .await?;
    permissions_layer_builder
        .append_directory(&FileInfo {
            path: Path::new("/var/minecraft").to_path_buf(),
            mode: 0o755,
            uid: 1000,
            gid: 1000,
            last_modified: 0,
        })
        .await?;
    // This is a commonly-used directory that Minecraft will want to *write* into
    permissions_layer_builder
        .append_directory(&FileInfo {
            path: Path::new("/var/minecraft/config").to_path_buf(),
            mode: 0o755,
            uid: 1000,
            gid: 1000,
            last_modified: 0,
        })
        .await?;
    permissions_layer_builder
        .append_directory(&FileInfo {
            path: Path::new("/var/minecraft/libraries").to_path_buf(),
            mode: 0o755,
            uid: 1000,
            gid: 1000,
            last_modified: 0,
        })
        .await?;
    let minecraft_layer = permissions_layer_builder.finalise().await?;
    info!(
        path = ?&minecraft_layer.path,
        digest = &minecraft_layer.digest(),
        "Created directory permissions Layer"
    );
    layers.push(minecraft_layer);

    ////////////////////////////////
    //// CONTAINER CONFIG
    ////////////////////////////////
    let mut cmd: Vec<String> = vec![];
    // We don't create a custom JAR with everything bundled in, so instead set the classpath to
    // the individual JAR libraries, and set the main class this way.
    cmd.push(
        "--class-path".to_string()
            + "="
            + &*(java_config
                .jars
                .into_iter()
                .map(|p| p.as_os_str().to_str().unwrap().to_string())
                .collect::<Vec<String>>()
                .join(":")),
    );
    cmd.extend(
        java_config
            .properties
            .iter()
            .map(|(k, v)| format!("-D{}={}", k, v)),
    );
    cmd.push(java_config.main_class);
    let config_file = ConfigFile {
        architecture: arch.oci(),
        os: oci_distribution::config::Os::Linux,
        config: Some(oci_distribution::config::Config {
            user: Some("1000:1000".to_string()),
            // The default Minecraft server port
            exposed_ports: Some(HashSet::from(["25565/tcp".to_string()])),
            entrypoint: Some(vec!["/bin/java".to_string()]),
            cmd: Some(cmd),
            working_dir: Some("/var/minecraft".to_string()),
            ..Default::default()
        }),
        history: Some(vec![oci_distribution::config::History {
            // No timestamp, for stability
            author: Some("mrpack-container".to_string()),
            ..Default::default()
        }]),
        rootfs: oci_distribution::config::Rootfs {
            r#type: "layers".to_string(),
            diff_ids: layers.iter().map(Blob::diff_id_digest).collect(),
        },
        ..Default::default()
    };

    // Write out the config JSON file.
    let mut config_blob_builder = JsonBlobBuilder::new(
        &oci_blob_dir,
        oci_distribution::manifest::IMAGE_CONFIG_MEDIA_TYPE.to_string(),
    )
    .await?;
    config_blob_builder.append_json(&config_file).await?;
    let config_blob = config_blob_builder.finalise().await?;
    info!(
        path = ?config_blob.path,
        digest = config_blob.digest(),
        entrypoint = config_file.config.as_ref().map(|c| c.entrypoint.as_ref()).flatten().map(|v| v.join(" ")).unwrap_or("[]".to_string()),
        cmd = config_file.config.as_ref().map(|c| c.cmd.as_ref()).flatten().map(|v| v.join(" ")).unwrap_or("[]".to_string()),
        working_dir = config_file.config.as_ref().map(|c| c.working_dir.as_ref()).flatten().unwrap_or(&"<none set>".to_string()),
        user = config_file.config.as_ref().map(|c| c.user.as_ref()).flatten().unwrap_or(&"<not set>".to_string()),
        "Wrote Container Config file"
    );

    ////////////////////////////////
    //// CONTAINER MANIFEST
    ////////////////////////////////
    let container_manifest = oci_distribution::manifest::OciImageManifest {
        media_type: Some(oci_distribution::manifest::OCI_IMAGE_MEDIA_TYPE.to_string()),
        config: OciDescriptor::from(&config_blob),
        layers: layers.iter().map(OciDescriptor::from).collect(),
        ..Default::default()
    };
    let mut manifest_blob_builder = JsonBlobBuilder::new(
        &oci_blob_dir,
        oci_distribution::manifest::OCI_IMAGE_MEDIA_TYPE.to_string(),
    )
    .await?;
    manifest_blob_builder
        .append_json(&container_manifest)
        .await?;
    let manifest_blob = manifest_blob_builder.finalise().await?;
    // Write the manifest. In a docker image this is a file in the root named manifest.json
    // in an OCI image it's also a blob.
    info!(
        path = ?manifest_blob.path,
        digest = manifest_blob.digest(),
        "Wrote Container Image Manifest file"
    );

    ////////////////////////////////
    //// TOP-LEVEL INDEX
    ////////////////////////////////
    let container_index = oci_distribution::manifest::OciImageIndex {
        schema_version: 2,
        media_type: Some(oci_distribution::manifest::OCI_IMAGE_INDEX_MEDIA_TYPE.to_string()),
        manifests: vec![oci_distribution::manifest::ImageIndexEntry {
            media_type: manifest_blob.media_type.to_string(),
            size: manifest_blob.compressed_size as i64,
            digest: manifest_blob.digest(),
            platform: Some(oci_distribution::manifest::Platform {
                architecture: arch.docker().to_string(),
                os: "linux".to_string(),
                os_version: None,
                os_features: None,
                variant: None,
                features: None,
            }),
            annotations: None,
        }],
        annotations: Some(HashMap::from([(
            oci_distribution::annotations::ORG_OPENCONTAINERS_IMAGE_REF_NAME.to_string(),
            index.name,
        )])),
    };
    let index_string = serde_json::to_string(&container_index)?;
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

    warn!(
        url = manifest.downloads.server.unwrap().url.to_string(),
        minecraft_version = index.dependencies.minecraft,
        // TODO don't just spam .unwrap() here
        expected_path_in_container = &in_container_minecraft_config
            .minecraft_jar_path
            .as_os_str()
            .to_str()
            .unwrap(),
        "You still need a Mojang JAR file, you can find the link in this log message"
    );

    info!("done!");
    Ok(())
}
