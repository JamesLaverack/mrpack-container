use crate::arch::Architecture;

pub struct Package {
    pub name: String,
    pub arch: Architecture,
    pub version: String,
}

impl Package {
    pub fn url(&self) -> Result<url::Url, url::ParseError> {
        // Yep. HTTP. Not HTTPS, it's a Debian thing.
        url::Url::parse("http://ftp.debian.org/debian/pool/main/")?
            .join(
                (self
                    .name
                    .chars()
                    .next()
                    .map(|c| c.to_string())
                    .unwrap_or("".to_string())
                    + "/")
                    .as_ref(),
            )?
            .join((self.name.to_string() + "/").as_ref())?
            .join(&format!(
                "{}_{}_{}.deb",
                self.name,
                self.version,
                self.arch.debian()
            ))
    }
}
