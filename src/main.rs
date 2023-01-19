use clap::Parser;
use oci_spec::distribution::RepositoryListBuilder;
use std::fs::File;
use std::path::Path;
use thiserror::Error;
use tracing::{error, info, warn};
use tracing_subscriber;

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

fn parse_image_name(image_name: String) -> Result<(url::Url, String), ImageNameParseError> {
    Ok((
        url::Url::parse("https://whatever").map_err(|_| ImageNameParseError { image_name })?,
        "foo".to_string(),
    ))
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
    let raw_resp = client
        .get("https://cgr.dev/v2/chainguard/jre/manifests/openjdk-jre-17")
        .header("Accept", "application/vnd.oci.image.index.v1+json")
        .send()
        .await?;
    let raw_bytes = &raw_resp.bytes().await?;
    let response_body = std::str::from_utf8(raw_bytes)?;

    let index: oci_spec::image::ImageIndex = match serde_json::from_str(response_body) {
        Ok(i) => i,
        Err(_) => {
            // Oh... maybe it's an error instead?
            let error_response: oci_spec::distribution::ErrorResponse =
                serde_json::from_str(response_body)?;
            for error in error_response.errors() {
                error!(
                    error_code = format!("{:?}", error.code()),
                    error_message = error.message(),
                    error_detail = error.detail(),
                    "Encountered error from registry"
                );
            }
            anyhow::bail!("Error from container registry")
        }
    };
    println!("{:#?}", index);
    // TODO Support platforms other than Amd64
    let os = oci_spec::image::Os::Linux;
    let arch = oci_spec::image::Arch::Amd64;
    let manifest = match index.manifests().into_iter().find(|m| match m.platform() {
        Some(p) => p.os() == &os && p.architecture() == &arch,
        None => false,
    }) {
        Some(m) => m,
        None => anyhow::bail!("Unable to find image for os/arch"),
    };
    info!(
        os = format!("{:?}", os),
        arch = format!("{:?}", arch),
        digest = manifest.digest(),
        "Found manifest for os and arch"
    );

    // download resources (multithread?)
    // unpack overrides & server overrides
    // download correct Wolfi jre image
    // Add layer to image with all mods
    // Emit completed container image
    Ok(())
}
