use anyhow::bail;
use chrono::prelude::Utc;
use clap::Parser;
use flate2::write::GzEncoder;
use flate2::Compression;
use oci_distribution::{
    client::ClientConfig, config::ConfigFile, manifest::OciDescriptor, secrets::RegistryAuth,
    Client, Reference,
};
use packfile::EnvType;
use sha2::{Digest, Sha256, Sha512};
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
use std::{collections::HashMap, fs};
use tar::Builder;
use tempfile::tempdir;
use thiserror::Error;
#[allow(unused_imports)]
use tracing::{debug, error, info, warn};
use tracing_subscriber;

mod download;
mod hash_writer;
mod modloaders;
#[allow(unused_imports)]
use modloaders::{fabric, forge, quilt};
mod mojang;
mod packfile;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[arg(help = "Path to the Modrinth Modpack file")]
    mr_pack_file: String,

    #[arg(short, long, help = "Output file")]
    output_file: Option<String>,

    #[arg(short, long, help = "Emit to STDOUT")]
    stdout: bool,

    #[arg(long, help = "Container Architecture", default_value = "amd64")]
    arch: String,

    #[arg(long, help = "Container OS", default_value = "linux")]
    os: String,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();
    if !args.stdout && args.output_file.is_none() {
        error!("One of --stdout or --output-file required");
        anyhow::bail!("One of --stdout or --output-file required");
    }
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

    // Make a temp dir which will be where we put everything that we're going to make on the
    // filesystem in the container.
    let dir = tempdir()?;
    let minecraft_dir = dir.path();
    info!(
        path = minecraft_dir.as_os_str().to_str().unwrap(),
        "Assembling Minecraft container layer"
    );

    // Get the Vanilla Minecraft server jar
    // Most installs will expect this to be downloaded as server.jar
    let minecraft_vanilla_jar = minecraft_dir.join("server.jar");
    let java_version =
        mojang::download_server_jar(minecraft_vanilla_jar.clone(), &index.dependencies.minecraft)
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
    let oci_blob_dir = oci_archive_dir.path().join("blobs").join("sha256");
    fs::create_dir_all(&oci_blob_dir)?;
    info!(
        path = oci_archive_dir.path().as_os_str().to_str().unwrap(),
        "Assembling new container as oci-archive"
    );

    let layer_tmp_path = oci_blob_dir.join("tmp.tar.gz");
    let mut layer_hasher = hash_writer::new(File::create(&layer_tmp_path)?, Sha256::new());
    {
        // Do the TAR creation in a block.
        // This is because as long as this GzEncoder exists, it borrows the hasher. We need
        // that borrow back to do the `.finalize_bytes()` later on.
        let enc = GzEncoder::new(&mut layer_hasher, Compression::best());
        let mut tar = Builder::new(enc);
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

    // Download the rest of the container image layers

    // Clone the os/arch and move them into the closure for lifetime reasons
    let osc = args.os.clone();
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
    // TODO Allow image override
    let base_image_ref: Reference = format!(
        "docker.io/eclipse-temurin:{}-jre",
        java_version.major_version
    )
    .parse()?;
    info!(
        java_version = java_version.major_version,
        base_image = base_image_ref.whole().as_str(),
        "Determined base container image"
    );

    let (mut manifest, _config_hash, raw_config) = registry_client
        .pull_manifest_and_config(&base_image_ref, &RegistryAuth::Anonymous)
        .await?;

    let mut config_file: ConfigFile = serde_json::from_str(&raw_config)?;
    info!(
        env = config_file
            .config
            .clone()
            .and_then(|config| config.env)
            .map(|env| env.join(", ")),
        "Loaded container config"
    );

    // Update the config for our application
    {
        // We don't create a custom JAR with everything bundled in, so instead set the classpath to
        // the individual JAR libraries, and set the main class this way.
        let mut c = config_file.config.unwrap_or_default();
        c.cmd = Some(
            [
                "java".to_string(),
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
        );
        c.working_dir = Some("/opt/minecraft".to_string());
        config_file.config = Some(c);
        // Update history with the fact that we've built this image, but otherwise use the base
        // image's history
        let mut h = config_file.history.unwrap_or_default();
        h.push(oci_distribution::config::History {
            created: Some(created_timestamp),
            author: Some("mrpack-container".to_string()),
            ..Default::default()
        });
        config_file.history = Some(h.to_vec());
        // Update RootFS
        config_file.created = Some(created_timestamp);
        config_file
            .rootfs
            .diff_ids
            .push(format!("sha256:{}", hex::encode(layer_checksum)));
    }
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
        tmp_dir = format!("{:?}", dir),
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
        digest: format!("sha256:{}", hex::encode(layer_checksum)),
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
        os = args.os,
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
                os: args.os,
                os_version: None,
                os_features: None,
                variant: None,
                features: None,
            }),
            annotations: None,
        }],
        annotations: Some(HashMap::from([(
            "org.opencontainers.image.ref.name".to_string(),
            index.name,
        )])),
    };
    let index_string = serde_json::to_string(&index)?;
    let index_bytes = index_string.as_bytes();
    let index_file_path = oci_archive_dir.path().join("index.json");
    let mut index_file = File::create(&index_file_path)?;
    index_file.write_all(index_bytes)?;
    info!(
        path = index_file_path.as_os_str().to_str().unwrap(),
        len_bytes = index_bytes.len(),
        "Wrote OCI Index file"
    );

    let layout_bytes = "{\"imageLayoutVersion\": \"1.0.0\"}".as_bytes();
    let layout_file_path = oci_archive_dir.path().join("oci-layout");
    let mut layout_file = File::create(&layout_file_path)?;
    layout_file.write_all(layout_bytes)?;
    info!(
        path = layout_file_path.as_os_str().to_str().unwrap(),
        len_bytes = layout_bytes.len(),
        "Wrote OCI layout file"
    );

    // Tar up the completed container image
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

    warn!(
        eula_url = "https://www.minecraft.net/en-us/eula".to_string(),
        "🚨Do NOT distribute this image publicly.🚨 It conatains Mojang property. See the Minecraft EULA.");
    info!("done!");
    Ok(())
}
