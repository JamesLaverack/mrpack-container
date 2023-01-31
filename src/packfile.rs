use serde::{Serialize, Deserialize};

// Based on Modrinth documentation https://docs.modrinth.com/docs/modpacks/format_definition/

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Index {
    pub format_version: u64,
    pub game: String,
    pub version_id: String,
    pub name: String,
    pub summary: Option<String>,
    pub files: Option<Vec<File>>,
    pub dependencies: Dependencies,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Dependencies {
    pub minecraft: String,
    pub forge: Option<String>,
    pub fabric_loader: Option<String>,
    pub quilt_loader: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct File {
    pub path: String,
    pub hashes: Hashes,
    pub env: Option<Env>,
    pub downloads: Vec<url::Url>,
    pub file_size: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Hashes {
    #[serde(with = "hex")]
    pub sha1: [u8; 20],
    #[serde(with = "hex")]
    pub sha512: [u8; 64],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Env {
    pub client: EnvType,
    pub server: EnvType,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum EnvType {
    Required,
    Optional,
    Unsupported,
}

