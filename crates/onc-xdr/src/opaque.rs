use std::borrow::Cow;
use std::io::{Read, Write};
use std::ops::Deref;

use crate::util::{add_padding, get_padding, zero_padding};
use crate::{Error, Pack, Unpack};

/// XDR variable-length opaque data -- a length-prefixed, zero-padded byte
/// string (RFC 4506 sec. 4.10).
///
/// Wraps a [`Cow`] so decoded data can be owned while data being encoded can
/// borrow from the caller, avoiding a copy on the send path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opaque<'a>(pub Cow<'a, [u8]>);

impl Opaque<'static> {
    /// Creates a new `Opaque` with owned data.
    #[must_use]
    pub const fn owned(data: Vec<u8>) -> Self {
        Opaque(Cow::Owned(data))
    }
}

impl<'a> Opaque<'a> {
    /// Creates a new `Opaque`.
    #[must_use]
    pub const fn new(data: Cow<'a, [u8]>) -> Self {
        Opaque(data)
    }

    /// Creates a new `Opaque` from a borrowed slice.
    #[must_use]
    pub const fn borrowed(data: &'a [u8]) -> Self {
        Opaque(Cow::Borrowed(data))
    }

    /// Returns the length of the opaque data.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the opaque data is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Extracts the owned data.
    ///
    /// Clones the data if it is not already owned.
    #[must_use]
    pub fn into_owned(self) -> Vec<u8> {
        self.0.into_owned()
    }

    /// Copies the opaque data into a new `Vec`.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Pack for Opaque<'_> {
    fn packed_size(&self) -> usize {
        4 + add_padding(self.0.len())
    }

    fn pack(&self, out: &mut impl Write) -> Result<usize, Error> {
        let mut bytes_written = 0;
        let len: u32 = self.0.len().try_into().map_err(|_| Error::ObjectTooLarge(self.0.len()))?;
        bytes_written += len.pack(out)?;

        out.write_all(&self.0).map_err(Error::Io)?;
        bytes_written += self.0.len();

        let padding = zero_padding(self.0.len());
        out.write_all(padding).map_err(Error::Io)?;
        bytes_written += padding.len();
        Ok(bytes_written)
    }
}

impl Unpack for Opaque<'static> {
    fn unpack(input: &mut impl Read) -> Result<(Self, usize), Error> {
        let (len, mut bytes_read) = u32::unpack(input)?;
        let len = len as usize;

        // Never size the allocation from the declared length. This decoder
        // handles every filename, symlink target, READ payload and file handle
        // on the wire, so a four-byte header claiming 4 GiB would otherwise
        // allocate and zero 4 GiB before read_exact discovers the reply is
        // short (CWE-789). read_bytes grows only as real bytes arrive.
        let buf = crate::util::read_bytes(input, len)?;
        bytes_read += len;

        let len = get_padding(len);
        if len > 0 {
            let mut pad_buf = [0u8; 4];
            #[expect(clippy::indexing_slicing, reason = "get_padding returns len & 3, so 0..=3, and the buffer is 4 bytes -- the slice is in range by construction")]
            input.read_exact(&mut pad_buf[..len]).map_err(Error::Io)?;
            bytes_read += len;
        }

        Ok((Opaque(Cow::Owned(buf)), bytes_read))
    }
}

impl AsRef<[u8]> for Opaque<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for Opaque<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for Opaque<'static> {
    fn from(vec: Vec<u8>) -> Self {
        Opaque(Cow::Owned(vec))
    }
}

impl<'a> From<&'a [u8]> for Opaque<'a> {
    fn from(slice: &'a [u8]) -> Self {
        Opaque(Cow::Borrowed(slice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_empty_round_trip() {
        // RFC 4506 sec 4.10: zero-length variable opaque, just the 4-byte length prefix.
        let op = Opaque::borrowed(b"");
        let mut buf = Vec::new();
        let written = op.pack(&mut buf).unwrap();
        assert_eq!(written, 4); // length prefix only
        assert_eq!(buf, [0, 0, 0, 0]);
        let (decoded, read) = Opaque::unpack(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.as_ref(), b"");
        assert_eq!(read, 4);
    }

    #[test]
    fn opaque_1_byte_pads_to_4() {
        // RFC 4506 sec 4.10: 1 data byte + 3 pad bytes.
        let op = Opaque::borrowed(&[0xAB]);
        let mut buf = Vec::new();
        let written = op.pack(&mut buf).unwrap();
        assert_eq!(written, 8); // 4 len + 1 data + 3 pad
        assert_eq!(&buf[0..4], [0, 0, 0, 1]); // length = 1
        assert_eq!(buf[4], 0xAB);
        assert_eq!(&buf[5..8], [0, 0, 0]); // padding
        let (decoded, read) = Opaque::unpack(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.as_ref(), &[0xAB]);
        assert_eq!(read, 8);
    }

    #[test]
    fn opaque_4_bytes_no_padding() {
        // RFC 4506 sec 4.10: 4 data bytes, already aligned.
        let data = [1u8, 2, 3, 4];
        let op = Opaque::borrowed(&data);
        let mut buf = Vec::new();
        let written = op.pack(&mut buf).unwrap();
        assert_eq!(written, 8); // 4 len + 4 data, no pad
        let (decoded, read) = Opaque::unpack(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.as_ref(), &data);
        assert_eq!(read, 8);
    }

    #[test]
    fn opaque_7_bytes_pads_to_8() {
        // RFC 4506 sec 4.10: 7 data bytes + 1 pad byte.
        let data = [10u8, 20, 30, 40, 50, 60, 70];
        let op = Opaque::borrowed(&data);
        let mut buf = Vec::new();
        let written = op.pack(&mut buf).unwrap();
        assert_eq!(written, 12); // 4 len + 7 data + 1 pad
        let (decoded, read) = Opaque::unpack(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.as_ref(), &data);
        assert_eq!(read, 12);
    }

    #[test]
    fn opaque_packed_size_includes_length_and_padding() {
        // packed_size = 4 (length prefix) + data_len rounded up to 4-byte boundary.
        assert_eq!(Opaque::borrowed(b"").packed_size(), 4);
        assert_eq!(Opaque::borrowed(b"x").packed_size(), 8); // 4 + pad(1)=4
        assert_eq!(Opaque::borrowed(b"xy").packed_size(), 8); // 4 + pad(2)=4
        assert_eq!(Opaque::borrowed(b"xyz").packed_size(), 8); // 4 + pad(3)=4
        assert_eq!(Opaque::borrowed(b"abcd").packed_size(), 8); // 4 + 4
        assert_eq!(Opaque::borrowed(b"abcde").packed_size(), 12); // 4 + pad(5)=8
    }

    #[test]
    fn opaque_borrowed_and_owned_produce_identical_wire_output() {
        let data = b"test payload";
        let borrowed = Opaque::borrowed(data);
        let owned = Opaque::owned(data.to_vec());

        let mut buf_b = Vec::new();
        let mut buf_o = Vec::new();
        let _ = borrowed.pack(&mut buf_b).unwrap();
        let _ = owned.pack(&mut buf_o).unwrap();
        assert_eq!(buf_b, buf_o);
    }

    #[test]
    fn opaque_packed_size_matches_actual_written() {
        // Verify packed_size agrees with the actual bytes written for various lengths.
        for len in 0..=17 {
            let data: Vec<u8> = (0u8..len).collect();
            let op = Opaque::borrowed(&data);
            let mut buf = Vec::new();
            let written = op.pack(&mut buf).unwrap();
            assert_eq!(op.packed_size(), written, "mismatch for data length {len}");
        }
    }

    // --- Golden vector: Opaque (RFC 4506 sec 4.10) ---

    #[test]
    fn golden_opaque_3_bytes() {
        // Hand-constructed wire bytes for Opaque([0xDE, 0xAD, 0xBE]):
        //   length(4) = 3, data(3) = DE AD BE, pad(1) = 00
        #[rustfmt::skip]
        const GOLDEN: [u8; 8] = [
            0x00, 0x00, 0x00, 0x03, // length = 3
            0xDE, 0xAD, 0xBE,       // data
            0x00,                    // padding to 4-byte boundary
        ];

        // Unpack from the golden bytes and verify field values.
        let (decoded, consumed) = Opaque::unpack(&mut &GOLDEN[..]).unwrap();
        assert_eq!(consumed, GOLDEN.len());
        assert_eq!(decoded.as_ref(), &[0xDE, 0xAD, 0xBE]);

        // Re-pack and verify exact byte equality.
        let mut repacked = Vec::new();
        let _ = decoded.pack(&mut repacked).unwrap();
        assert_eq!(repacked, GOLDEN);
    }

    #[test]
    fn golden_opaque_8_bytes_no_padding() {
        // Opaque([0x01..=0x08]): 8 data bytes, already 4-byte aligned.
        #[rustfmt::skip]
        const GOLDEN: [u8; 12] = [
            0x00, 0x00, 0x00, 0x08, // length = 8
            0x01, 0x02, 0x03, 0x04, // data bytes 1-4
            0x05, 0x06, 0x07, 0x08, // data bytes 5-8
        ];

        let (decoded, consumed) = Opaque::unpack(&mut &GOLDEN[..]).unwrap();
        assert_eq!(consumed, 12);
        assert_eq!(decoded.as_ref(), &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

        let mut repacked = Vec::new();
        let _ = decoded.pack(&mut repacked).unwrap();
        assert_eq!(repacked, GOLDEN);
    }
}
