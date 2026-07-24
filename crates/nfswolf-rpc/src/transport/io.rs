//! Asynchronous I/O traits for reading and writing bytes.
//!
//! Deliberately minimal and runtime-agnostic: the protocol clients need only
//! "fill this buffer" and "drain this buffer", so depending on a specific
//! runtime's I/O traits would buy nothing and would make it awkward to slot in
//! a proxied stream or a test double.

/// Trait to read bytes asynchronously.
pub trait AsyncRead: Send {
    /// Read bytes from the stream into the provided buffer.
    ///
    /// Returns the number of bytes read, which must not exceed `buf.len()`.
    /// A return of `Ok(0)` signals end of stream.
    fn async_read(&mut self, buf: &mut [u8]) -> impl Future<Output = std::io::Result<usize>> + Send;

    /// Read exactly enough bytes to fill the buffer.
    ///
    /// Returns [`UnexpectedEof`] if the stream ends first.  A short read is
    /// routine on a socket -- the kernel hands over whatever has arrived -- so
    /// this loops rather than assuming one call suffices.
    ///
    /// [`UnexpectedEof`]: std::io::ErrorKind::UnexpectedEof
    fn async_read_exact(&mut self, buf: &mut [u8]) -> impl Future<Output = std::io::Result<()>> + Send {
        async move {
            let mut buf = buf;
            while !buf.is_empty() {
                let n = self.async_read(buf).await?;
                if n == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                }
                // Reborrow through take() so the remainder can be assigned back
                // into `buf`; slicing it in place would not satisfy the borrow
                // checker.  get_mut rejects an implementation that claims to
                // have read more than it was given, which would otherwise
                // panic here.
                let consumed = std::mem::take(&mut buf);
                buf = consumed.get_mut(n..).ok_or_else(|| std::io::Error::other("async_read reported more bytes than the buffer holds"))?;
            }
            Ok(())
        }
    }
}

/// Trait to write bytes asynchronously.
pub trait AsyncWrite: Send {
    /// Write bytes to the stream from the provided buffer.
    ///
    /// Returns the number of bytes written, which must not exceed `buf.len()`.
    fn async_write(&mut self, buf: &[u8]) -> impl Future<Output = std::io::Result<usize>> + Send;

    /// Write the entire buffer to the stream.
    ///
    /// Returns [`WriteZero`] if the stream stops accepting bytes before the
    /// buffer is drained.
    ///
    /// [`WriteZero`]: std::io::ErrorKind::WriteZero
    fn async_write_all(&mut self, buf: &[u8]) -> impl Future<Output = std::io::Result<()>> + Send {
        async move {
            let mut buf = buf;
            while !buf.is_empty() {
                let n = self.async_write(buf).await?;
                if n == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
                }
                buf = buf.get(n..).ok_or_else(|| std::io::Error::other("async_write reported more bytes than the buffer holds"))?;
            }
            Ok(())
        }
    }
}
