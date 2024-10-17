#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Architecture {
    X86_64,
    ARM64,
}

impl Architecture {
    pub fn parse(name: &str) -> Option<Architecture> {
        match name {
            "amd64" | "x64" | "x86_64" => Some(Architecture::X86_64),
            "arm64" | "arm" | "aarch64" => Some(Architecture::ARM64),
            _ => None,
        }
    }

    pub fn oci(&self) -> oci_distribution::config::Architecture {
        match self {
            Architecture::X86_64 => oci_distribution::config::Architecture::Amd64,
            Architecture::ARM64 => oci_distribution::config::Architecture::Arm64,
        }
    }

    pub fn linux(&self) -> &str {
        match self {
            Architecture::X86_64 => "x86_64",
            Architecture::ARM64 => "aarch64",
        }
    }

    pub fn debian(&self) -> &str {
        match self {
            Architecture::X86_64 => "amd64",
            Architecture::ARM64 => "arm64",
        }
    }

    pub fn docker(&self) -> &str {
        match self {
            Architecture::X86_64 => "amd64",
            Architecture::ARM64 => "arm64",
        }
    }
}
