use digest::Digest;
use std::io::{Error, Result, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use sha2::Sha256;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub struct HashWriter<W: Write, D: Digest> {
    write: W,
    digest: D,
}

pub struct HashWriterAsync<AW: AsyncWrite, D: Digest> {
    inner: AW,
    digest: D,
}

impl<AW: AsyncWrite, D: Digest> AsyncWrite for HashWriterAsync<AW, D> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, Error>> {
        self.digest.update(buf);
        self.inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Error>> {
        self.inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Error>> {
        self.inner.poll_shutdown(cx)
    }
}

impl<AW: AsyncWrite, D: Digest> HashWriterAsync<AW, D> {
    pub fn new(self, digest: D, writer: AW) -> HashWriterAsync<AW, D> {
        return HashWriterAsync {
            digest,
            inner: writer,
        };
    }
    pub async fn into_inner(mut self) -> (AW, digest::Output<D>) {
        return (self.inner, self.digest.finalize())
    }
}

impl<AW: AsyncWrite> HashWriterAsync<AW, Sha256> {
    pub fn new(self, writer: Box<dyn AsyncWrite>) -> HashWriterAsync<AW, Sha256> {
        return HashWriterAsync{
            digest: Sha256::new(),
            inner: writer,
        }
    }

    pub async fn into_inner(mut self) -> (AW, [u8; 32]) {
        return (self.inner, self.digest.finalize().into())
    }
}

/// Construct a new HashWriter from the given writer and digest.
///
/// Doing so will move both the writer and the digest into this struct. To get the
/// result out of the digest, you'll need to use the `finalize()` function on the
/// HashWriter. For some digest types, `finalize_bytes()` is also implmented that
/// returns an approrpately sized `[u8]`.
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
        Into::into(self.finalize())
    }
}

impl<W: Write> HashWriter<W, sha2::Sha256> {
    pub fn finalize_bytes(self) -> [u8; 32] {
        Into::into(self.finalize())
    }
}

impl<W: Write> HashWriter<W, sha2::Sha512> {
    pub fn finalize_bytes(self) -> [u8; 64] {
        Into::into(self.finalize())
    }
}
