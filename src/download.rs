use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use std::io::Write;
/*
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
*/
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

