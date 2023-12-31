use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use std::{error::Error, io::Write, marker::{Send, Sync, Unpin}};

/// Stream content from a bytes stream to a writer until the stream is complete
pub async fn stream_to_writer<
    E: Error + Send + Sync + 'static,
    S: Stream<Item = std::result::Result<Bytes, E>> + Unpin,
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
