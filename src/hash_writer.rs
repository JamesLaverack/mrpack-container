use digest::Digest;
use std::io::{Result, Write};

pub struct HashWriter<W: Write, D: Digest> {
    write: W,
    digest: D,
}

pub fn new<W: Write, D: Digest>(write: W, digest: D) -> HashWriter<W, D> {
    HashWriter { write, digest }
}

impl<W: Write, D: Digest> Write for HashWriter<W, D> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.digest.update(buf);
        self.write.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.write.flush()
    }
}

impl<W: Write, D: Digest> HashWriter<W, D> {
    pub fn finalize(self) -> digest::Output<D> {
        self.digest.finalize()
    }
}

impl<W: Write> HashWriter<W, sha1::Sha1> {
    pub fn finalize_bytes(self) -> [u8; 20] {
        Into::into(self.digest.finalize())
    }
}

impl<W: Write> HashWriter<W, sha2::Sha256> {
    pub fn finalize_bytes(self) -> [u8; 32] {
        Into::into(self.digest.finalize())
    }
}

impl<W: Write> HashWriter<W, sha2::Sha512> {
    pub fn finalize_bytes(self) -> [u8; 64] {
        Into::into(self.digest.finalize())
    }
}
