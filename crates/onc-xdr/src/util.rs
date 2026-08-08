//! Padding arithmetic and length-hardened reads for XDR.
//!
//! RFC 4506 sec. 3 requires every XDR item to occupy a multiple of four bytes,
//! with the remainder zero-filled.  Getting this wrong desynchronises the whole
//! stream, so the padding helpers here are used by every variable-length type
//! rather than open-coding the arithmetic at each site.
//!
//! The read helpers exist for a second reason.  Every length on the wire is
//! chosen by the peer, and a security tool talks to servers that may be
//! actively hostile, so a declared length is never used to size an allocation
//! directly -- see [`PREALLOC_CAP`].

use std::io::{Read, Write};

use super::Error;

/// Rounds a length up to the next 4-byte boundary.
#[inline]
pub(crate) const fn add_padding(sz: usize) -> usize {
    (sz + 3) & !3
}

/// Returns how many pad bytes follow an item of the given length.
#[inline]
#[expect(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    reason = "two's-complement negation computes (4 - len % 4) % 4 branchlessly; \
              the mask with 3 bounds the result to 0..=3 so neither cast can lose data"
)]
pub(crate) const fn get_padding(len: usize) -> usize {
    (-(len as isize) & 3) as usize
}

/// Returns a slice of zero bytes to write after an item of the given length.
#[inline]
pub(crate) fn zero_padding(len: usize) -> &'static [u8] {
    const ZEROES: [u8; 3] = [0, 0, 0];
    let pad = get_padding(len);
    #[expect(clippy::indexing_slicing, reason = "get_padding returns len & 3, so 0..=3, and ZEROES is 3 bytes -- the slice is in range by construction")]
    &ZEROES[..pad]
}

/// Ceiling on how much buffer a single declared length may reserve up front.
///
/// A length field is attacker-controlled: a four-byte header claiming 4 GiB
/// costs the peer nothing to send but would cost us the allocation. Decoders
/// reserve at most this much regardless of what was declared and grow only as
/// real bytes arrive, so a forged length cannot amplify a small reply into a
/// large allocation. Honest inputs decode identically -- this bounds only the
/// speculative reservation.
pub const PREALLOC_CAP: usize = 1 << 20; // 1 MiB / ~1M elements

/// Reads exactly `len` bytes without trusting `len` for pre-allocation.
///
/// Returns `UnexpectedEof` when fewer than `len` bytes are available, matching
/// `read_exact`'s contract for honest inputs. See [`PREALLOC_CAP`].
pub fn read_bytes(input: &mut impl Read, len: usize) -> super::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(len.min(PREALLOC_CAP));
    let read = input.take(len as u64).read_to_end(&mut buf).map_err(Error::Io)?;
    if read != len {
        return Err(Error::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)));
    }
    Ok(buf)
}

/// Reserves capacity for a declared element count, bounded by [`PREALLOC_CAP`].
///
/// The count-prefixed-array equivalent of [`read_bytes`]: use it instead of
/// `Vec::with_capacity(count)` whenever `count` came off the wire.
#[must_use]
pub fn vec_with_capacity<T>(count: usize) -> Vec<T> {
    Vec::with_capacity(count.min(PREALLOC_CAP))
}

/// Writes 1, 2, or 3 zero bytes to reach a 4-byte boundary.
///
/// Any other value writes nothing, so callers can pass a raw `len % 4`.
pub fn write_pad(out: &mut impl Write, pad: usize) -> super::Result<()> {
    match pad {
        1 => out.write_all(&[0u8]).map_err(Error::Io),
        2 => out.write_all(&[0u8; 2]).map_err(Error::Io),
        3 => out.write_all(&[0u8; 3]).map_err(Error::Io),
        _ => Ok(()),
    }
}

/// Reads and discards 1, 2, or 3 padding bytes.
pub fn skip_pad(input: &mut impl Read, pad: usize) -> super::Result<()> {
    match pad {
        1 => {
            let mut b = [0u8; 1];
            input.read_exact(&mut b).map_err(Error::Io)
        },
        2 => {
            let mut b = [0u8; 2];
            input.read_exact(&mut b).map_err(Error::Io)
        },
        3 => {
            let mut b = [0u8; 3];
            input.read_exact(&mut b).map_err(Error::Io)
        },
        _ => Ok(()),
    }
}

/// Packs an XDR string: 4-byte length, bytes, zero-pad to a 4-byte boundary.
pub fn pack_string(s: &str, out: &mut impl Write) -> super::Result<usize> {
    use super::Pack;
    let bytes = s.as_bytes();
    let len = u32::try_from(bytes.len()).map_err(|_| Error::ObjectTooLarge(bytes.len()))?;
    let mut n = len.pack(out)?;
    out.write_all(bytes).map_err(Error::Io)?;
    n += bytes.len();
    let pad = get_padding(bytes.len());
    write_pad(out, pad)?;
    n += pad;
    Ok(n)
}

/// Unpacks an XDR string: 4-byte length, bytes, padding.
///
/// Invalid UTF-8 is replaced rather than rejected -- a server may return
/// arbitrary bytes in a name field, and that is a finding to report rather than
/// a reason to abort the decode.
pub fn unpack_string(input: &mut impl Read) -> super::Result<(String, usize)> {
    use super::Unpack;
    let (len, mut n) = u32::unpack(input)?;
    let len = len as usize;
    let buf = read_bytes(input, len)?;
    n += len;
    let pad = get_padding(len);
    skip_pad(input, pad)?;
    n += pad;
    Ok((String::from_utf8_lossy(&buf).into_owned(), n))
}

/// Returns the packed size of an XDR string, including length prefix and padding.
#[must_use]
pub const fn string_packed_size(s: &str) -> usize {
    let len = s.len();
    4 + len + get_padding(len)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_add_padding() {
        assert_eq!(add_padding(0), 0);
        assert_eq!(add_padding(1), 4);
        assert_eq!(add_padding(2), 4);
        assert_eq!(add_padding(3), 4);
        assert_eq!(add_padding(4), 4);
        assert_eq!(add_padding(5), 8);
        assert_eq!(add_padding(6), 8);
        assert_eq!(add_padding(7), 8);
        assert_eq!(add_padding(8), 8);
    }

    #[test]
    fn test_zero_padding() {
        assert_eq!(zero_padding(0), &[]);
        assert_eq!(zero_padding(1), &[0, 0, 0]);
        assert_eq!(zero_padding(2), &[0, 0]);
        assert_eq!(zero_padding(3), &[0]);
        assert_eq!(zero_padding(4), &[]);
        assert_eq!(zero_padding(5), &[0, 0, 0]);
        assert_eq!(zero_padding(6), &[0, 0]);
        assert_eq!(zero_padding(7), &[0]);
    }

    #[test]
    fn read_bytes_rejects_short_input() {
        let mut src = &b"abc"[..];
        assert!(read_bytes(&mut src, 8).is_err());
    }

    #[test]
    fn read_bytes_does_not_preallocate_forged_length() {
        // A forged 4 GiB length against a 3-byte body must fail cleanly rather
        // than attempt the reservation.
        let mut src = &b"abc"[..];
        assert!(read_bytes(&mut src, usize::MAX).is_err());
    }

    #[test]
    fn string_round_trip_pads_to_boundary() {
        for s in ["", "a", "ab", "abc", "abcd", "abcde"] {
            let mut buf = Vec::new();
            let written = pack_string(s, &mut buf).expect("pack");
            assert_eq!(written, string_packed_size(s), "size mismatch for {s:?}");
            assert!(written.is_multiple_of(4), "not 4-byte aligned for {s:?}");
            let (got, read) = unpack_string(&mut buf.as_slice()).expect("unpack");
            assert_eq!(got, s);
            assert_eq!(read, written);
        }
    }
}
