use anyhow::{Context, bail};
use async_compression::tokio::bufread::GzipDecoder;
use async_zip::tokio::read::fs::ZipFileReader;
use clap::Parser;
use futures::io::ErrorKind;
use futures::prelude::*;
use modloaders::{fabric, quilt};
use oci_distribution::{config::ConfigFile, manifest::OciDescriptor};
use packfile::EnvType;
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::{collections::HashSet, fs::File};
use tar::EntryType;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::task::JoinSet;
use tokio_util::compat::FuturesAsyncReadCompatExt;
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber;

use crate::LayerType::{Overrides, ServerOverrides};
use crate::arch::Architecture;
use crate::modloaders::{InContainerMinecraftConfig, JavaConfig};
use crate::oci_blob::{
    Blob,
    json::JsonBlobBuilder,
    layer::{FileInfo, TarLayerBuilder},
};
use crate::packfile::Dependencies;

mod adoptium;
mod arch;
mod deb;
mod hash_writer;
mod modloaders;
mod mojang;
mod oci_blob;
mod packfile;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum LayerType {
    Dependency(Architecture, String),
    Java(Architecture),
    Modloader,
    Download(String),
    Overrides,
    ServerOverrides,
    Permissions,
}

impl LayerType {
    fn applicable_for(&self, arch: Architecture) -> bool {
        match self {
            LayerType::Dependency(a, _) => arch == *a,
            LayerType::Java(a) => arch == *a,
            // For layer types that don't have an architecture, they're always to be included
            _ => true,
        }
    }
}

struct BuiltLayer {
    layer_type: LayerType,
    blob: Option<Blob>,
    extra_config: Option<JavaConfig>,
}

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[arg(help = "Path to the Modrinth Modpack file")]
    mr_pack_file: String,

    #[arg(long, short, help = "Output directory")]
    output: String,

    #[arg(long, visible_alias = "arch", num_args = 1.., value_delimiter = ' ', help = "Container Architectures", default_value = "amd64 arm64")]
    arches: Vec<String>,

    #[arg(long, help = "Fixed Java version")]
    java_version: Option<String>,

    #[arg(long, help = "Debug logging output")]
    debug: bool,
}

async fn load_index_file(mrpack_file: &ZipFileReader) -> anyhow::Result<packfile::Index> {
    // Search through for the modrinth index file. This doesn't scan the whole file, just the ZIP
    // file's index which is stored at the end. Then open a reader to that file based on the index number.
    let mut index_file_reader = mrpack_file
        .reader_with_entry(
            match mrpack_file.file().entries().iter().position(|f| {
                f.filename()
                    .as_str()
                    .map(|n| n == "modrinth.index.json")
                    .unwrap_or_default()
            }) {
                Some(file) => file,
                None => {
                    anyhow::bail!("Failed to find modrinth.index.json file in .mrpack archive");
                }
            },
        )
        .await?;
    // Read the entire index file into memory. It *should* be a relatively short JSON text file.
    let mut index_bytes =
        Vec::with_capacity(index_file_reader.entry().uncompressed_size() as usize);
    index_file_reader
        .read_to_end_checked(&mut index_bytes)
        .await?;

    Ok(serde_json::from_slice(&index_bytes)?)
}

async fn extract_overrides_to_layer<P: AsRef<Path>>(
    mrpack_file: &ZipFileReader,
    oci_blob_dir: P,
    in_container_minecraft_config: &InContainerMinecraftConfig,
    overrides: &str,
) -> anyhow::Result<Option<Blob>> {
    // Find the list of applicable overrides by looking at the filenames
    let mut entries = mrpack_file
        .file()
        .entries()
        .iter()
        .enumerate()
        .filter(|(_, e)| {
            e.filename()
                .as_str()
                .map(|f| f.starts_with(overrides))
                .unwrap_or_default()
        })
        .collect::<Vec<(usize, &async_zip::StoredZipEntry)>>();

    // Sort the list by filename for stability
    entries.sort_by_key(|(_, e)| e.filename().as_str().unwrap_or_default());

    // If none, exit early
    if entries.len() == 0 {
        return Ok(None);
    }

    // Otherwise, build a layer for them
    let mut olayer_builder = TarLayerBuilder::new(oci_blob_dir).await?;

    // Loop over the entries in order and write them into the layer.
    for (i, e) in &entries {
        if e.dir().unwrap_or_default() {
            debug!(path = e.filename().as_str()?, "Skipping directory");
            continue;
        }
        // In theory, it's possible to read from the zipfile entries in parallel. But that doesn't
        // help us get any faster because we can't *write* them in parallel. (Not without some
        // filesystem handle shenanigans anyway.)
        let relative_path = Path::new(e.filename().as_str()?).strip_prefix(overrides)?;
        let writable = guess_is_writable(&relative_path);
        let in_container_filepath = in_container_minecraft_config
            .minecraft_working_dir
            .join(relative_path);
        let mut reader = BufReader::new(mrpack_file.reader_without_entry(*i).await?.compat());

        olayer_builder
            .append_file(
                &in_container_filepath,
                &FileInfo {
                    mode: if writable { 0o0666 } else { 0o0644 },
                    uid: 0,
                    gid: 0,
                    last_modified: 0,
                },
                e.uncompressed_size(),
                &mut reader,
            )
            .await
            .context(format!(
                "Failed to append file {} from overrides",
                &in_container_filepath
                    .as_os_str()
                    .to_str()
                    .unwrap_or_default()
            ))?;
        info!(
            path = &in_container_filepath
                .as_os_str()
                .to_str()
                .unwrap_or_default(),
            size = e.uncompressed_size(),
            overrides = overrides,
            writable = if writable { "yes" } else { "no" },
            "Unpacked overrides file"
        );
    }

    // Finalise the layer
    let layer = olayer_builder.finalise().await?;
    info!(
        path = ?&layer.path,
        digest = &layer.digest(),
        overrides = overrides,
        num_files = entries.len(),
        "Created Overrides Layer"
    );
    Ok(Some(layer))
}

// Some files and directories are expected to be writable by various mods. However, the MRPACK
// format does not encode any permission information. Instead, we'll have to guess if it should
// be writable or read-only based on the filename.
fn guess_is_writable(path: &Path) -> bool {
    path.iter().next().map(|p| p == "config").unwrap_or(false)
}

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

    // Parse architectures
    let mut arches = args
        .arches
        .iter()
        .map(|a| {
            Architecture::parse(a).ok_or(anyhow::anyhow!(format!(
                "Architecture '{}' not supported",
                a
            )))
        })
        .collect::<anyhow::Result<Vec<Architecture>>>()?;
    arches.sort();
    arches.dedup();

    // Load the pack file
    let path = Path::new(&args.mr_pack_file);
    if !path.exists() {
        anyhow::bail!("Pack file not found");
    }
    let mrpack_file = ZipFileReader::new(path).await?;
    let index = load_index_file(&mrpack_file).await?;
    info!(
        path = "file://".to_owned() + &path.as_os_str().to_str().unwrap(),
        name = index.name,
        version = index.version_id,
        "Loaded Modrinth modpack file"
    );

    // Create the output directories
    let oci_archive_dir: &Path = args.output.as_ref();
    if oci_archive_dir.exists() {
        warn!(
            path = ?oci_archive_dir,
            "Output directory already exists, some files may be overwritten.")
    }
    let oci_blob_dir = oci_archive_dir.join("blobs").join("sha256");
    tokio::fs::create_dir_all(&oci_blob_dir).await?;
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

    let in_container_minecraft_config = modloaders::InContainerMinecraftConfig {
        lib_dir: Path::new("/usr/local/minecraft/lib").to_path_buf(),
        minecraft_jar_path: Path::new("/usr/local/minecraft/server.jar").to_path_buf(),
        minecraft_working_dir: Path::new("/var/minecraft").to_path_buf(),
    };

    // Build layers in parallel
    let mut join_set = JoinSet::new();

    // There's a load of cloning going on here to make copies of things to give to each task. This
    // is okay, vs using ARCs, because the size of the cloned things are very small.

    for arch in &arches {
        join_set.spawn(deb::install_debian_package(
            oci_blob_dir.clone(),
            deb::Package {
                name: "libc6".to_string(),
                version: "2.36-9+deb12u10".to_string(),
                arch: *arch,
            },
        ));
        join_set.spawn(install_jre(
            *arch,
            oci_blob_dir.clone(),
            java_version.clone(),
        ));
    }

    join_set.spawn(install_modloader(
        oci_blob_dir.clone(),
        in_container_minecraft_config.clone(),
        index.dependencies.clone(),
    ));

    if let Some(files) = index.files {
        for mrfile in files {
            join_set.spawn(install_external_file(
                oci_blob_dir.clone(),
                in_container_minecraft_config.clone(),
                mrfile,
            ));
        }
    }

    join_set.spawn(install_overrides(
        oci_blob_dir.clone(),
        in_container_minecraft_config.clone(),
        mrpack_file.clone(),
    ));
    join_set.spawn(install_server_overrides(
        oci_blob_dir.clone(),
        in_container_minecraft_config.clone(),
        mrpack_file.clone(),
    ));

    join_set.spawn(install_directory_permissions(
        oci_blob_dir.clone(),
        in_container_minecraft_config.clone(),
    ));

    info!(
        arches = ?arches,
        "Building image layers");
    let mut layers: Vec<BuiltLayer> = vec![];
    while let Some(join) = join_set.join_next().await {
        match join {
            Ok(res) => match res {
                Ok(layer) => layers.push(layer),
                Err(err) => {
                    error!(
                        error = err.to_string(),
                        "Encountered error while building layer"
                    );
                    join_set.abort_all();
                    return Err(err);
                }
            },
            Err(err) => {
                error!(
                    error = err.to_string(),
                    "Encountered error with concurrent execution"
                );
                join_set.abort_all();
                return Err(anyhow::Error::from(err));
            }
        }
    }

    // Sort the layers, they could be in a random order. So we need to get them into a stable one that's repeatable over runs.
    layers.sort_by_key(|f| f.layer_type.clone());

    // Find the extra_config. In the current design there should only be one. It's possible there
    // could be more in the future, so we might need to merge it then. But for now we don't need
    // too.
    let java_config = match layers
        .iter()
        .filter_map(|l| match &l.extra_config {
            Some(ec) => Some(ec),
            None => None,
        })
        .next()
    {
        Some(extra_config) => extra_config,
        None => anyhow::bail!(
            "Failed to find internal config for Java, should have been provided by the modloader"
        ),
    };

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
                .clone()
                .into_iter()
                .map(|p| p.as_os_str().to_str().unwrap().to_string())
                .collect::<Vec<String>>()
                .join(":")),
    );
    let mut opts = java_config
        .properties
        .iter()
        .map(|(k, v)| format!("-D{}={}", k, v))
        .collect::<Vec<String>>();
    // Sort required for stability between runs
    opts.sort();
    cmd.extend(opts);
    cmd.push(java_config.main_class.clone());

    let config_files = arches
        .iter()
        .map(|arch| {
            (
                *arch,
                ConfigFile {
                    architecture: arch.oci(),
                    os: oci_distribution::config::Os::Linux,
                    config: Some(oci_distribution::config::Config {
                        user: Some("1000:1000".to_string()),
                        // The default Minecraft server port
                        exposed_ports: Some(HashSet::from(["25565/tcp".to_string()])),
                        entrypoint: Some(vec!["/bin/java".to_string()]),
                        cmd: Some(cmd.clone()),
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
                        diff_ids: layers
                            .iter()
                            .filter(|blob| blob.layer_type.applicable_for(*arch))
                            .filter_map(|b| match &b.blob {
                                Some(blob) => Some(blob),
                                None => None,
                            })
                            .map(|b| b.diff_id_digest())
                            .collect(),
                    },
                    ..Default::default()
                },
            )
        })
        .collect::<HashMap<Architecture, ConfigFile>>();

    // Write out the config JSON file.
    let mut config_blobs: HashMap<Architecture, Blob> = HashMap::new();
    for (arch, config_file) in config_files {
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
        config_blobs.insert(arch, config_blob);
    }

    ////////////////////////////////
    //// CONTAINER MANIFEST
    ////////////////////////////////
    let mut manifest_blobs: HashMap<Architecture, Blob> = HashMap::new();
    for (arch, config_blob) in config_blobs {
        let container_manifest = oci_distribution::manifest::OciImageManifest {
            media_type: Some(oci_distribution::manifest::OCI_IMAGE_MEDIA_TYPE.to_string()),
            config: OciDescriptor::from(&config_blob),
            layers: layers
                .iter()
                .filter(|blob| blob.layer_type.applicable_for(arch))
                .filter_map(|b| match &b.blob {
                    Some(blob) => Some(blob),
                    None => None,
                })
                .map(|b| OciDescriptor::from(b))
                .collect(),
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
        info!(
            path = ?&manifest_blob.path,
            digest = &manifest_blob.digest(),
            "Wrote Container Image Manifest file"
        );
        manifest_blobs.insert(arch, manifest_blob);
    }

    ////////////////////////////////
    //// TOP-LEVEL INDEX
    ////////////////////////////////
    let container_index = oci_distribution::manifest::OciImageIndex {
        schema_version: 2,
        media_type: Some(oci_distribution::manifest::OCI_IMAGE_INDEX_MEDIA_TYPE.to_string()),
        manifests: manifest_blobs
            .iter()
            .map(
                |(arch, manifest_blob)| oci_distribution::manifest::ImageIndexEntry {
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
                    annotations: Some(HashMap::from([(
                        oci_distribution::annotations::ORG_OPENCONTAINERS_IMAGE_REF_NAME
                            .to_string(),
                        format!("{}-{}", index.version_id, arch.docker().to_string()),
                    )])),
                },
            )
            .collect(),
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

    info!(
        jar_download_url = manifest.downloads.clone().server.unwrap().url.to_string(),
        minecraft_version = index.dependencies.minecraft,
        // TODO don't just spam .unwrap() here
        expected_path_in_container = &in_container_minecraft_config
            .minecraft_jar_path
            .as_os_str()
            .to_str()
            .unwrap(),
        sha1_checksum = hex::encode_upper(manifest.downloads.clone().server.unwrap().sha1),
        "You still need a Mojang JAR file"
    );
    info!(
        read_the_eula_url = "https://www.minecraft.net/en-us/eula",
        expected_path_in_container = &in_container_minecraft_config
            .eula_path()
            .as_os_str()
            .to_str()
            .unwrap(),
        file_contents_to_accept = "eula=true",
        "You still need a file to accept the Minecraft EULA"
    );

    info!(
        "The created container is in OCI format, also known as oci-dir format. Tools that operate only on Docker images won't work. You can convert it into an oci-archive format by compressing the output directory into a tarball."
    );

    if container_index.manifests.len() > 1 {
        let names = container_index
            .manifests
            .iter()
            .map(|m| {
                m.annotations
                    .as_ref()
                    .map(|a| {
                        a[oci_distribution::annotations::ORG_OPENCONTAINERS_IMAGE_REF_NAME].clone()
                    })
                    .unwrap_or_default()
            })
            .collect::<Vec<String>>()
            .join(", ");
        info!(
            names = names,
            "This container is a multi-architecture OCI image. You may need to specify the name of the specific architecture you want. The individual images are named with their architectures."
        )
    }

    info!("done!");
    Ok(())
}

async fn install_overrides<P: AsRef<Path>>(
    oci_blob_dir: P,
    in_container_minecraft_config: InContainerMinecraftConfig,
    mrpack_file: ZipFileReader,
) -> anyhow::Result<BuiltLayer> {
    Ok(BuiltLayer {
        layer_type: Overrides,
        blob: extract_overrides_to_layer(
            &mrpack_file,
            &oci_blob_dir,
            &in_container_minecraft_config,
            "overrides",
        )
        .await?,
        extra_config: None,
    })
}
async fn install_server_overrides<P: AsRef<Path>>(
    oci_blob_dir: P,
    in_container_minecraft_config: InContainerMinecraftConfig,
    mrpack_file: ZipFileReader,
) -> anyhow::Result<BuiltLayer> {
    Ok(BuiltLayer {
        layer_type: ServerOverrides,
        blob: extract_overrides_to_layer(
            &mrpack_file,
            &oci_blob_dir,
            &in_container_minecraft_config,
            "server-overrides",
        )
        .await?,
        extra_config: None,
    })
}
async fn install_directory_permissions<P: AsRef<Path>>(
    oci_blob_dir: P,
    in_container_minecraft_config: InContainerMinecraftConfig,
) -> anyhow::Result<BuiltLayer> {
    let mut permissions_layer_builder = TarLayerBuilder::new(&oci_blob_dir).await?;
    // Set permissions on some directories
    permissions_layer_builder
        .append_directory(
            "/tmp",
            &FileInfo {
                // World writable
                mode: 0o777,
                uid: 0,
                gid: 0,
                last_modified: 0,
            },
        )
        .await
        .context("Failed to write /tmp directory permissions")?;
    permissions_layer_builder
        .append_directory(
            "/var",
            &FileInfo {
                mode: 0o755,
                uid: 0,
                gid: 0,
                last_modified: 0,
            },
        )
        .await
        .context("Failed to write /var/ directory permissions")?;
    permissions_layer_builder
        .append_directory(
            &in_container_minecraft_config.minecraft_working_dir,
            &FileInfo {
                mode: 0o755,
                uid: 1000,
                gid: 1000,
                last_modified: 0,
            },
        )
        .await
        .context("Failed to write Minecraft working directory permissions")?;
    // This is a commonly-used directory that Minecraft will want to *write* into
    permissions_layer_builder
        .append_directory(
            in_container_minecraft_config
                .minecraft_working_dir
                .join("config"),
            &FileInfo {
                mode: 0o755,
                uid: 1000,
                gid: 1000,
                last_modified: 0,
            },
        )
        .await
        .context("Failed to write Minecraft config directory permissions")?;
    permissions_layer_builder
        .append_directory(
            in_container_minecraft_config
                .minecraft_working_dir
                .join("libraries"),
            &FileInfo {
                mode: 0o755,
                uid: 1000,
                gid: 1000,
                last_modified: 0,
            },
        )
        .await
        .context("Failed to write Minecraft libraries directory permissions")?;
    let minecraft_layer = permissions_layer_builder.finalise().await?;
    info!(
        path = ?&minecraft_layer.path,
        digest = &minecraft_layer.digest(),
        "Created directory permissions Layer"
    );
    Ok(BuiltLayer {
        layer_type: LayerType::Permissions,
        blob: Some(minecraft_layer),
        extra_config: None,
    })
}

async fn install_external_file<P: AsRef<Path>>(
    oci_blob_dir: P,
    in_container_minecraft_config: InContainerMinecraftConfig,
    mrfile: packfile::File,
) -> anyhow::Result<BuiltLayer> {
    if let Some(env) = &mrfile.env {
        match env.server {
            EnvType::Required => {}
            EnvType::Optional => {
                info!(path = &mrfile.path, "including optional server-side mod");
            }
            EnvType::Unsupported => {
                info!(path = &mrfile.path, "skipping unsupported server-side mod");
                // This isn't an error, just return a BuiltLayer with an empty blob, and we'll
                // filter it out later.
                return Ok(BuiltLayer {
                    layer_type: LayerType::Download(mrfile.path.to_string()),
                    blob: None,
                    extra_config: None,
                });
            }
        }
    }
    if mrfile.downloads.len() == 0 {
        bail!("File had no provided download URLs")
    }

    let mut container_path = in_container_minecraft_config.minecraft_working_dir.clone();
    container_path.push(&mrfile.path);

    let u = mrfile.downloads.get(0).unwrap();
    let mut file_layer_builder = TarLayerBuilder::new(&oci_blob_dir).await?;
    let digest: [u8; 64] = file_layer_builder
        .append_file_from_url(
            &container_path,
            FileInfo {
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
        .await
        .context(format!("Failed to append download of {}", &u))?
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
    Ok(BuiltLayer {
        blob: Some(file_layer),
        layer_type: LayerType::Download(mrfile.path.to_string()),
        extra_config: None,
    })
}

async fn install_modloader<P: AsRef<Path>, C: Into<InContainerMinecraftConfig>>(
    oci_blob_dir: P,
    in_container_minecraft_config: C,
    deps: Dependencies,
) -> anyhow::Result<BuiltLayer> {
    // Install the mod loader
    // The way we need to configure the container later will depend on the mod loader. So we'll get
    // a configuration function back
    Ok(if let Some(fabric_version) = &deps.fabric_loader {
        info!(fabric_version = &fabric_version, "Using Fabric modloader");
        let (java_config, blob) = fabric::build_fabric_layer(
            oci_blob_dir.as_ref(),
            &in_container_minecraft_config.into(),
            &deps.minecraft,
            &fabric_version,
        )
        .await?;
        BuiltLayer {
            layer_type: LayerType::Modloader,
            blob: Some(blob),
            extra_config: Some(java_config),
        }
    } else if let Some(quilt_version) = &deps.quilt_loader {
        info!(quilt_version = &quilt_version, "Using Quilt modloader");
        let (java_config, blob) = quilt::build_quilt_layer(
            oci_blob_dir.as_ref(),
            &in_container_minecraft_config.into(),
            &deps.minecraft,
            &quilt_version,
        )
        .await?;
        BuiltLayer {
            layer_type: LayerType::Modloader,
            blob: Some(blob),
            extra_config: Some(java_config),
        }
    } else if let Some(_forge_version) = &deps.forge {
        // TODO Support Forge
        anyhow::bail!("forge not yet supported");
    } else if let Some(_neoforge_version) = &deps.neoforge {
        // TODO Support Neoforge
        anyhow::bail!("neoforge not yet supported");
    } else {
        anyhow::bail!("No modloader found");
    })
}

async fn install_jre<P: AsRef<Path>, S: AsRef<str>>(
    arch: Architecture,
    oci_blob_dir: P,
    java_version: S,
) -> anyhow::Result<BuiltLayer> {
    let jre_download = adoptium::get_jre_download(java_version.as_ref(), arch).await?;
    info!(
        url = jre_download.url.to_string(),
        sha256 = hex::encode_upper(jre_download.sha256),
        "Got JRE download info"
    );

    // Download and stream into a layer
    let request = reqwest::get(jre_download.url).await?;
    let mut jre_tar_stream = BufReader::new(GzipDecoder::new(BufReader::new(
        tokio_util::io::StreamReader::new(
            request
                .bytes_stream()
                .map_err(|e| std::io::Error::new(ErrorKind::Other, e)),
        ),
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
                    .append_directory(
                        &p,
                        &FileInfo {
                            mode: 0o755,
                            uid: 0,
                            gid: 0,
                            last_modified: 0,
                        },
                    )
                    .await
                    .context("Failed to append directory from JVM tarfile")?;
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
                        &p,
                        &FileInfo {
                            mode,
                            uid: 0,
                            gid: 0,
                            last_modified: 0,
                        },
                        file_size,
                        &mut (&mut jre_tar_stream).take(size),
                    )
                    .await
                    .context("Failed to append file from JVM tarfile")?;
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
                        &p,
                        &FileInfo {
                            mode,
                            uid: 0,
                            gid: 0,
                            last_modified: 0,
                        },
                        &target,
                    )
                    .await
                    .context("Failed to append symlink from JVM tarfile")?;
            }
            _ => {
                bail!("Unsupported entry type {:?}", entry_type)
            }
        }
    }
    // Write an extra symlink
    jre_layer_builder
        .append_symlink(
            "/bin/java",
            &FileInfo {
                mode: 0o755,
                uid: 0,
                gid: 0,
                last_modified: 0,
            },
            "/usr/local/java/bin/java",
        )
        .await
        .context("Failed to append symlink for JVM at /bin/java")?;
    let jre_layer = jre_layer_builder.finalise().await?;
    info!(
        path = ?jre_layer.path,
        digest = jre_layer.digest(),
        "Created JRE Layer"
    );
    Ok(BuiltLayer {
        blob: Some(jre_layer),
        layer_type: LayerType::Java(arch),
        extra_config: None,
    })
}
