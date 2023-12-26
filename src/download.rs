use bytes::Bytes;
use crypto::digest::Digest;
use futures_util::{Stream, StreamExt};

pub async fn stream_and_hash<
    S: Stream<Item = reqwest::Result<Bytes>> + std::marker::Unpin,
    W: std::io::Write,
>(
    mut stream: S,
    mut file: W,
    digest: &mut impl Digest,
) -> anyhow::Result<usize> {
    let mut total = 0;
    while let Some(item) = stream.next().await {
        let chunk = item?;
        digest.input(&chunk);
        file.write_all(&chunk)?;
        total += chunk.len();
    }
    Ok(total)
}
