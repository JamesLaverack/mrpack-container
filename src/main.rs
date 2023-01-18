use std::path::Path;
use clap::Parser;
use tracing::{info, warn, error};
use tracing_subscriber;
use std::fs::File;
use anyhow::Result;
use oci_spec::distribution::RepositoryListBuilder;

mod packfile;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    #[arg(help = "Path to the Modrinth Modpack file")]
    mr_pack_file: String,
}

fn main() -> Result<()> {
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
        },
    };
    let index: packfile::Index = serde_json::from_reader(index_file)?;

    info!(name = index.name,
        version = index.version_id,
        "Loading modpack");
    // TODO Check we're using only valid download URLs

    // TODO Use the Mojang version API to get the Java version, for now assume 17
    // TODO Allow image override
    let base_image = "cgr.dev/chainguard/jre:openjdk-jre-17";
    let list = RepositoryListBuilder::default()
            .repositories(vec!["cgr.dev/chainguard/jre".to_owned()])
            .build()?;

    // download resources (multithread?)
    // unpack overrides & server overrides
    // download correct Wolfi jre image
    // Add layer to image with all mods
    // Emit completed container image
    Ok(())
}
