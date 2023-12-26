use anyhow::bail;
use clap::Parser;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use crypto::sha2::Sha512;
use packfile::EnvType;
use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::path::Path;
use tempfile::tempdir;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use tracing_subscriber;

mod download;
mod modloaders;
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
    info!("Running MRContainer");

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
    info!(
        path = dir.path().as_os_str().to_str().unwrap(),
        "Assembling Minecraft container layer"
    );

    let minecraft_dir = dir.path().join("opt").join("minecraft");
    fs::create_dir_all(&minecraft_dir)?;
    info!(
        minecraft_dir = "/opt/minecraft",
        "Created Minecraft dir in container filesystem"
    );

    // Get the Vanilla Minecraft server jar
    // Most installs will expect this to be downloaded as server.jar
    let minecraft_vanilla_jar = minecraft_dir.join("server.jar");
    mojang::download_server_jar(minecraft_vanilla_jar.clone(), &index.dependencies.minecraft)
        .await?;

    // Install the mod loader
    if let Some(_fabric_version) = &index.dependencies.fabric_loader {
        anyhow::bail!("forge not supported");
    } else if let Some(quilt_version) = &index.dependencies.quilt_loader {
        quilt::download_quilt(
            minecraft_dir.clone(),
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

    // TODO Check we're using only valid download URLs
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
            let mut path = minecraft_dir.clone();
            // TODO check for path injection here
            path.push(&mrfile.path);
            fs::create_dir_all(&path.parent().unwrap())?;
            let file = File::create(&path)?;
            let mut hasher = Sha512::new();
            let size = download::stream_and_hash(request.bytes_stream(), file, &mut hasher)
                .await?;
            let mut checksum: [u8; 64] = [0; 64];
            hasher.result(&mut checksum);
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
                sha512 = hasher.result_str(),
                path = mrfile.path,
                url = u,
                "Downloaded file"
            );
        }
    }
    extract_overrides(&mut zipfile, &minecraft_dir, "overrides")?;
    extract_overrides(&mut zipfile, &minecraft_dir, "server-overrides")?;

    info!("Assembled on filesystem");
    std::thread::sleep(std::time::Duration::from_millis(10000));
    // TODO Use the Mojang version API to get the Java version, for now assume 17
    // TODO Allow image override
    let client = reqwest::Client::new();
    let index_bytes = client
        .get("https://registry.hub.docker.com/v2/library/eclipse-temurin/manifests/17-jre-alpine")
        .header("Accept", "application/vnd.oci.image.index.v1+json")
        .send()
        .await?
        .bytes()
        .await?;
    let index: oci_spec::image::ImageIndex = match parse_registry_response(&index_bytes) {
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

    // TODO Support platforms other than Amd64
    let os = oci_spec::image::Os::Linux;
    let arch = oci_spec::image::Arch::Amd64;
    let description = match index.manifests().into_iter().find(|m| match m.platform() {
        Some(p) => p.os() == &os && p.architecture() == &arch,
        None => false,
    }) {
        Some(m) => m,
        None => anyhow::bail!("Unable to find image for os/arch"),
    };
    info!(
        os = format!("{:?}", os),
        arch = format!("{:?}", arch),
        digest = description.digest(),
        "Found manifest for os and arch"
    );

    let manifest_bytes = client
        // Oh I just love string templating user-provided data into a URL...
        // TODO Don't.
        .get(
            "https://registry.hub.docker.com/v2/library/eclipse-temurin/manifests/".to_owned()
                + description.digest(),
        )
        .header("Accept", "application/vnd.oci.image.manifest.v1+json")
        .send()
        .await?
        .bytes()
        .await?;
    let manifest: oci_spec::image::ImageManifest = match parse_registry_response(&manifest_bytes) {
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

    let config_bytes = client
        // Oh I just love string templating user-provided data into a URL...
        // TODO Don't.
        .get(
            "https://registry.hub.docker.com/v2/library/eclipse-temurin/blobs".to_owned()
                + manifest.config().digest(),
        )
        .header("Accept", "application/vnd.oci.image.config.v1+json")
        .send()
        .await?
        .bytes()
        .await?;
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
    // Grab all the images to a tmp directory
    let dir = env::temp_dir();
    info!(tmp_dir = format!("{:?}", dir), "Using temporary directory");

    for layer in manifest.layers() {
        info!(digest = layer.digest(), "Downloading layer");
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
    }
    // download resources (multithread?)
    // unpack overrides & server overrides
    // download correct Wolfi jre image
    // Add layer to image with all mods
    // Emit completed container image
    Ok(())
}
