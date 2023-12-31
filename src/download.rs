use bytes::Bytes;
use digest::{Digest, FixedOutputReset};
use futures_util::{Stream, StreamExt};
use std::io::{Result, Write};
#[allow(unused_imports)]
use tracing::{debug, error, info, warn};

pub async fn stream_and_hash<
    S: Stream<Item = reqwest::Result<Bytes>> + std::marker::Unpin,
    W: Write,
    D: digest::Digest,
>(
    mut stream: S,
    mut file: W,
    digest: &mut D,
) -> anyhow::Result<usize> {
    let mut total = 0;
    let d = digest;
    while let Some(item) = stream.next().await {
        let chunk = item?;
        Digest::update(d, &chunk);
        file.write_all(&chunk)?;
        total += chunk.len();
    }
    Ok(total)
}

pub async fn stream_to_writer<
    S: Stream<Item = reqwest::Result<Bytes>> + std::marker::Unpin,
    W: Write,
>(
    mut stream: S,
    mut file: W,
) -> anyhow::Result<usize> {
    let mut total = 0;
    while let Some(item) = stream.next().await {
        let chunk = item?;
        file.write_all(&chunk)?;
        total += chunk.len();
    }
    Ok(total)
}

pub struct HashWriter<'a, W: Write, D: Digest> {
    write: W,
    digest: &'a mut D,
}

pub fn new<W: Write, D: Digest>(write: W, digest: &mut D) -> HashWriter<W, D> {
    HashWriter { write, digest }
}

impl<W: Write, D: Digest> Write for HashWriter<'_, W, D> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.digest.update(buf);
        self.write.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.write.flush()
    }
}

impl<W: Write, D: Digest + FixedOutputReset> HashWriter<'_, W, D> {
    pub fn finalize_reset(self) -> digest::Output<D> {
        self.digest.finalize_reset()
    }
}

