use anyhow::bail;
use clap::Parser;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use futures_util::StreamExt;
use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use tempfile::tempdir;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use tracing_subscriber;

mod packfile;
mod download;

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

fn parse_image_name(image_name: String) -> Result<(url::Url, String), ImageNameParseError> {
    Ok((
        url::Url::parse("https://whatever").map_err(|_| ImageNameParseError { image_name })?,
        "foo".to_string(),
    ))
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt::init();
    info!("Running MRContainer");
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
            anyhow::bail!("Failed to find modrinth.index.json file in mrpack archive");
        }
    };
    let index: packfile::Index = serde_json::from_reader(index_file)?;

    info!(
        name = index.name,
        version = index.version_id,
        "Loading modpack"
    );
    // TODO Check we're using only valid download URLs

    // TODO Use the Mojang version API to get the Java version, for now assume 17
    // TODO Allow image override
    let client = reqwest::Client::new();
    let index_bytes = client
        .get("https://cgr.dev/v2/chainguard/jre/manifests/openjdk-jre-17")
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

    println!("{:#?}", index);
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
        .get("https://cgr.dev/v2/chainguard/jre/manifests/".to_owned() + description.digest())
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
    println!("{:#?}", manifest);

    let config_bytes = client
        // Oh I just love string templating user-provided data into a URL...
        // TODO Don't.
        .get("https://cgr.dev/v2/chainguard/jre/blobs/".to_owned() + manifest.config().digest())
        .header("Accept", "application/vnd.oci.image.config.v1+json")
        .send()
        .await?
        .bytes()
        .await?;
    println!("{:?}", config_bytes);
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
    println!("{:#?}", config);
    // Grab all the images to a tmp directory
    let dir = env::temp_dir();
    info!(tmp_dir = format!("{:?}", dir), "Using temporary directory");

    for layer in manifest.layers() {
        info!(digest = layer.digest(), "Downloading layer");
        let mut hasher = Sha256::new();
        let layer_res = client
            // Oh I just love string templating user-provided data into a URL...
            // TODO Don't.
            .get("https://cgr.dev/v2/chainguard/jre/blobs/".to_owned() + layer.digest())
            .header("Accept", "application/vnd.oci.image.layer.v1.tar+gzip")
            .send()
            .await?;
        let mut filepath = dir.clone();
        filepath.push(layer.digest());
        let file = File::create(filepath)?;
        download::stream_to_file_and_hash(layer_res.bytes_stream(), file, &mut hasher).await?;
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
