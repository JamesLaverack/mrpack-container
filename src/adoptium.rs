use std::path::PathBuf;

use anyhow::anyhow;
#[allow(unused_imports)]
use tracing::{debug, error, info, warn};
use url::Url;

use crate::arch::Architecture;

pub struct JREDownload {
    pub url: url::Url,
    pub sha256: [u8; 32],
}

fn adoptium_arch(arch: &Architecture) -> &str {
    match arch {
        Architecture::X86_64 => "x64",
        Architecture::ARM64 => "aarch64",
    }
}

pub async fn get_jre_download(
    java_version: &str,
    arch: Architecture,
) -> anyhow::Result<JREDownload> {
    let mut api_url = PathBuf::new();
    api_url.push("v3/assets/latest/");
    api_url.push(java_version);
    api_url.push("hotspot");
    let base = Url::parse("https://api.adoptium.net/")?;
    let mut path = base.join(
        api_url
            .to_str()
            .ok_or(anyhow!("URL path construction error"))?,
    )?;
    path.query_pairs_mut()
        .clear()
        .append_pair("os", "alpine-linux")
        .append_pair("architecture", adoptium_arch(&arch))
        .append_pair("image_type", "jre");
    info!(
        arch = ?&arch,
        url = path.to_string(),
        "Requesting JRE information from Eclipse Adoptium"
    );
    let request = reqwest::get(path).await?;
    let response: serde_json::Value = serde_json::from_str(&request.text().await?)?;
    let mut checksum = [0u8; 32];
    hex::decode_to_slice(
        response[0]["binary"]["package"]["checksum"]
            .as_str()
            .ok_or(anyhow!("JSON error (checksum)"))?,
        &mut checksum as &mut [u8],
    )?;
    return Ok(JREDownload {
        url: Url::parse(
            response[0]["binary"]["package"]["link"]
                .as_str()
                .ok_or(anyhow!("JSON error (link)"))?,
        )?,
        sha256: checksum,
    });
}
