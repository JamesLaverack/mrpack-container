use digest::Digest;
use pin_project_lite::pin_project;
use sha2::Sha256;
use std::io::{Error, Result, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// TODO Replace with tokio_util::io::InspectWriter

pub struct HashWriter<W: Write, D: Digest> {
    write: W,
    digest: D,
}

pin_project! {
    pub struct HashWriterAsync<AW, D> {
        #[pin]
        inner: AW,
        digest: D,
        total_bytes_written: usize,
    }
}

pin_project! {
    pub struct HashReaderAsync<AR, D> {
        #[pin]
        inner: AR,
        digest: D,
    }
}
impl<AR, D> AsyncRead for HashReaderAsync<AR, D>
where
    AR: AsyncRead,
    D: Digest,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let start_len = buf.filled().len();
        let projection = self.project();
        let r = projection.inner.poll_read(cx, buf);
        let bytes_read = buf.filled().len() - start_len;
        if bytes_read > 0 {
            projection.digest.update(&buf.filled()[start_len..]);
        }
        return r;
    }
}
impl<AR, D> HashReaderAsync<AR, D>
where
    D: digest::Digest,
{
    pub fn new(digest: D, inner: AR) -> HashReaderAsync<AR, D> {
        return HashReaderAsync { digest, inner };
    }
    pub fn into_inner(self) -> (AR, digest::Output<D>) {
        return (self.inner, self.digest.finalize());
    }
}

impl<AW, D> AsyncWrite for HashWriterAsync<AW, D>
where
    AW: AsyncWrite,
    D: Digest,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, Error>> {
        let projection = self.project();
        let r = projection.inner.poll_write(cx, buf);
        if let Poll::Ready(Ok(num_bytes_written)) = r {
            projection.digest.update(&buf[..num_bytes_written]);
            *projection.total_bytes_written += num_bytes_written;
        }
        return r;
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Error>> {
        self.project().inner.poll_shutdown(cx)
    }
}

impl<AW, D> HashWriterAsync<AW, D>
where
    D: digest::Digest,
{
    pub fn new(digest: D, inner: AW) -> HashWriterAsync<AW, D> {
        return HashWriterAsync {
            digest,
            inner,
            total_bytes_written: 0,
        };
    }
    #[allow(dead_code)]
    pub fn into_inner(self) -> (AW, digest::Output<D>, usize) {
        return (self.inner, self.digest.finalize(), self.total_bytes_written);
    }
}

impl<AW> HashWriterAsync<AW, Sha256> {
    pub fn new_sha256(inner: AW) -> HashWriterAsync<AW, Sha256> {
        return Self::new(Sha256::new(), inner);
    }

    pub fn into_inner_sha256(self) -> (AW, [u8; 32], usize) {
        return (
            self.inner,
            self.digest.finalize().into(),
            self.total_bytes_written,
        );
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
