use anyhow::bail;
use clap::Parser;
use flate2::write::GzEncoder;
use flate2::Compression;
use oci_distribution::{secrets::RegistryAuth, Client, Reference};
use packfile::EnvType;
use sha2::{Digest, Sha256, Sha512};
use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::path::Path;
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

fn parse_registry_response<'a, T: serde::Deserialize<'a>>(
    raw: &'a [u8],
) -> Result<T, RegistryError> {
    match serde_json::from_slice(&raw) {
        Ok(r) => Ok(r),
        Err(e) => match serde_json::from_slice(&raw) {
            Ok(er) => Err(RegistryError::ErrorResponse(er)),
            Err(_) => Err(RegistryError::ParseError(e)),
        },
    }
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
    // Setup code
    let args = Args::parse();
    tracing_subscriber::fmt::init();
    info!("Running mrpack-container");

    // Load the pack file and extract it
    let path = Path::new(&args.mr_pack_file);
    if !path.exists() {
        anyhow::bail!("File not found");
    }
    // TODO Support reading from HTTPS
    // TODO Support reading from S3
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
    if let Some(_fabric_version) = &index.dependencies.fabric_loader {
        anyhow::bail!("forge not supported");
    } else if let Some(quilt_version) = &index.dependencies.quilt_loader {
        quilt::download_quilt(
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
    info!(
        path = oci_archive_dir.path().as_os_str().to_str().unwrap(),
        "Assembling new container as oci-archive"
    );

    let layer_tmp_path = oci_archive_dir.path().join("tmp.tar.gz");
    let mut hasher = hash_writer::new(File::create(&layer_tmp_path)?, Sha256::new());
    {
        // Do the file writing in a block, so that references to the hash writer and
        // everything else are dropped and then we can read the result from the hasher
        let enc = GzEncoder::new(&mut hasher, Compression::default());
        let mut tar = Builder::new(enc);
        info!("appending to TAR");
        tar.append_dir_all("opt/minecraft", &minecraft_dir)?;
    }
    let checksum = hasher.finalize_bytes();
    //hasher.finalize_into(&mut Into::into(layer_hash));
    // Rename to it's hash
    info!("rename");
    let hash_name = oci_archive_dir.path().join(hex::encode(checksum));
    fs::rename(layer_tmp_path, &hash_name)?;
    info!(
        path = hash_name.to_str(),
        hash = hex::encode_upper(checksum),
        "Assembled minecraft layer"
    );

    // Checksum it, and then rename it to match the checksum
    // TODO Change to a more effecient method of doing this
    //

    let client_config = oci_distribution::client::ClientConfig {
        platform_resolver: Some(Box::new(|manifests| {
            manifests
                .iter()
                .find(|entry| {
                    entry.platform.as_ref().map_or(false, |platform| {
                        // TODO support other architectures and platforms
                        platform.os == "linux" && platform.architecture == "amd64"
                    })
                })
                .map(|e| e.digest.clone())
        })),
        ..Default::default()
    };
    let mut registry_client = Client::new(client_config);
    // TODO Allow image override
    let base_image_ref: Reference = format!(
        "docker.io/eclipse-temurin:{}-jre-alpine",
        java_version.major_version
    )
    .parse()?;

    let (manifest, config, image_hash) = registry_client
        .pull_manifest_and_config(&base_image_ref, &RegistryAuth::Anonymous)
        .await?;

    /*
    let config: oci_spec::image::ImageConfiguration = match parse_registry_response(&config_bytes) {
        Ok(i) => i,
        Err(e) => match e {
            RegistryError::ErrorResponse(er) => {
                for error in er.errors() {
                    error!(
                        error_code = format!("{:?}", error.code()),
                        error_message = error.message(),
                        error_detail = error.detail(),
                        "Encountered error from registry"
                    );
                }
                bail!("error from registry");
            }
            RegistryError::ParseError(pe) => {
                error!("couldn't parse JSON");
                bail!(pe)
            }
        },
    };
    */

    // Grab all the images to a tmp directory
    let dir = env::temp_dir();
    info!(tmp_dir = format!("{:?}", dir), "Using temporary directory");

    for layer in manifest.layers {
        info!(
            digest = layer.digest,
            media_type = layer.media_type,
            size_bytes = layer.size,
            urls = layer.urls.and_then(|s| Some(s.join(", "))),
            "Downloading layer"
        );
        /*
        let mut hasher = Sha256::new();
        let layer_res = client
            // Oh I just love string templating user-provided data into a URL...
            // TODO Don't.
            .get(
                "https://registry.hub.docker.com/v2/library/eclipse-temurin/blobs".to_owned()
                    + layer.digest(),
            )
            .header("Accept", "application/vnd.oci.image.layer.v1.tar+gzip")
            .send()
            .await?;
        let mut filepath = dir.clone();
        filepath.push(layer.digest());
        let file = File::create(filepath)?;
        download::stream_and_hash(layer_res.bytes_stream(), file, &mut hasher).await?;
        if *layer.digest() != "sha256:".to_owned() + &hasher.result_str() {
            warn!(
                expected = layer.digest(),
                actual = hasher.result_str(),
                "Layer did not match digest!"
            );
        } else {
            debug!(
                actual = hasher.result_str(),
                "Layer digest computed and matched"
            );
        }
        info!(digest = layer.digest(), "Download complete");
        */
    }
    // Add layer to image with all mods
    // Emit completed container image
    info!("done!");
    std::thread::sleep_ms(10000);
    panic!("test panic");
    Ok(())
}
