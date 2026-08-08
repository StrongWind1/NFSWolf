use std::io::{Read, Write};

use crate::util::{add_padding, get_padding, zero_padding};
use crate::{Error, Pack, Result, Unpack};

impl Pack for Vec<u32> {
    fn packed_size(&self) -> usize {
        4 + self.len() * 4
    }

    fn pack(&self, out: &mut impl Write) -> Result<usize> {
        let mut bytes_written = 0;

        bytes_written += u32::try_from(self.len()).map_err(|_| Error::ObjectTooLarge(self.len()))?.pack(out)?;

        for item in self {
            bytes_written += item.pack(out)?;
        }

        Ok(bytes_written)
    }
}

impl Unpack for Vec<u32> {
    fn unpack(input: &mut impl Read) -> Result<(Self, usize)> {
        let mut bytes_read = 0;

        let (len, len_bytes) = u32::unpack(input)?;
        bytes_read += len_bytes;

        let mut vec = crate::util::vec_with_capacity(len as usize);

        for _ in 0..len {
            let (item, item_bytes) = u32::unpack(input)?;
            bytes_read += item_bytes;
            vec.push(item);
        }

        Ok((vec, bytes_read))
    }
}

impl Pack for u32 {
    fn packed_size(&self) -> usize {
        4
    }

    fn pack(&self, out: &mut impl Write) -> Result<usize> {
        let bytes = self.to_be_bytes();
        out.write_all(&bytes).map_err(Error::Io)?;
        Ok(4)
    }
}

impl Unpack for u32 {
    fn unpack(input: &mut impl Read) -> Result<(Self, usize)> {
        let mut bytes = [0u8; 4];
        input.read_exact(&mut bytes).map_err(Error::Io)?;
        Ok((Self::from_be_bytes(bytes), 4))
    }
}

impl Pack for u64 {
    fn packed_size(&self) -> usize {
        8
    }

    fn pack(&self, out: &mut impl Write) -> Result<usize> {
        let bytes = self.to_be_bytes();
        out.write_all(&bytes).map_err(Error::Io)?;
        Ok(8)
    }
}

impl Unpack for u64 {
    fn unpack(input: &mut impl Read) -> Result<(Self, usize)> {
        let mut bytes = [0u8; 8];
        input.read_exact(&mut bytes).map_err(Error::Io)?;
        Ok((Self::from_be_bytes(bytes), 8))
    }
}

impl Pack for bool {
    fn packed_size(&self) -> usize {
        4
    }

    #[expect(clippy::bool_to_int_with_if, reason = "we want to be explicit")]
    fn pack(&self, out: &mut impl Write) -> Result<usize> {
        let val = if *self { 1u32 } else { 0u32 };
        val.pack(out)
    }
}

impl Unpack for bool {
    fn unpack(input: &mut impl Read) -> Result<(Self, usize)> {
        let (val, bytes_read) = u32::unpack(input)?;
        match val {
            0 => Ok((false, bytes_read)),
            1 => Ok((true, bytes_read)),
            _ => Err(Error::InvalidEnumValue(val)),
        }
    }
}

impl<const N: usize> Pack for [u8; N] {
    fn packed_size(&self) -> usize {
        add_padding(N)
    }

    fn pack(&self, out: &mut impl Write) -> Result<usize> {
        let mut bytes_written = 0;
        out.write_all(self).map_err(Error::Io)?;
        bytes_written += N;

        let padding = zero_padding(N);
        out.write_all(padding).map_err(Error::Io)?;
        bytes_written += padding.len();

        Ok(bytes_written)
    }
}

impl<const N: usize> Unpack for [u8; N] {
    fn unpack(input: &mut impl Read) -> Result<(Self, usize)> {
        let mut bytes_read = 0;
        let mut buf = [0u8; N];
        input.read_exact(&mut buf).map_err(Error::Io)?;
        bytes_read += N;

        let padding = get_padding(N);
        if padding > 0 {
            let mut pad_buf = [0u8; 4];
            #[expect(clippy::indexing_slicing, reason = "get_padding returns len & 3, so 0..=3, and the buffer is 4 bytes -- the slice is in range by construction")]
            input.read_exact(&mut pad_buf[..padding]).map_err(Error::Io)?;
            bytes_read += padding;
        }

        Ok((buf, bytes_read))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- u32 (RFC 4506 sec 4.2) ---

    #[test]
    fn u32_round_trip() {
        // RFC 4506 sec 4.2: "An XDR signed integer is a 32-bit datum"
        for val in [0u32, 1, 255, 65535, u32::MAX] {
            let mut buf = Vec::new();
            let written = val.pack(&mut buf).unwrap();
            assert_eq!(written, 4);
            let (decoded, read) = u32::unpack(&mut buf.as_slice()).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(read, 4);
        }
    }

    #[test]
    fn u32_big_endian_on_wire() {
        // RFC 4506 sec 3: XDR integers are big-endian (most significant byte first).
        let mut buf = Vec::new();
        let _ = 0x0102_0304u32.pack(&mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);
    }

    #[test]
    fn u32_packed_size_is_four() {
        assert_eq!(42u32.packed_size(), 4);
    }

    // --- u64 (RFC 4506 sec 4.5) ---

    #[test]
    fn u64_round_trip() {
        // RFC 4506 sec 4.5: unsigned hyper, 8 bytes.
        for val in [0u64, 1, u64::from(u32::MAX), u64::MAX] {
            let mut buf = Vec::new();
            let written = val.pack(&mut buf).unwrap();
            assert_eq!(written, 8);
            let (decoded, read) = u64::unpack(&mut buf.as_slice()).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(read, 8);
        }
    }

    #[test]
    fn u64_big_endian_on_wire() {
        // RFC 4506 sec 3: all integers are big-endian.
        let mut buf = Vec::new();
        let _ = 0x0102_0304_0506_0708u64.pack(&mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn u64_packed_size_is_eight() {
        assert_eq!(99u64.packed_size(), 8);
    }

    // --- bool (RFC 4506 sec 4.4) ---

    #[test]
    fn bool_encodes_as_u32_zero_or_one() {
        // RFC 4506 sec 4.4: "enum { FALSE = 0, TRUE = 1 }"
        let mut buf = Vec::new();
        let _ = false.pack(&mut buf).unwrap();
        assert_eq!(buf, [0, 0, 0, 0]);

        buf.clear();
        let _ = true.pack(&mut buf).unwrap();
        assert_eq!(buf, [0, 0, 0, 1]);
    }

    #[test]
    fn bool_round_trip() {
        for val in [true, false] {
            let mut buf = Vec::new();
            let _ = val.pack(&mut buf).unwrap();
            let (decoded, read) = bool::unpack(&mut buf.as_slice()).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(read, 4);
        }
    }

    #[test]
    fn bool_rejects_invalid_discriminant() {
        // Any u32 value other than 0 or 1 is not a valid bool.
        for bad in [2u32, 3, 255, u32::MAX] {
            let mut buf = Vec::new();
            let _ = bad.pack(&mut buf).unwrap();
            let err = bool::unpack(&mut buf.as_slice()).unwrap_err();
            assert!(matches!(err, Error::InvalidEnumValue(v) if v == bad));
        }
    }

    // --- [u8; N] fixed-length opaque (RFC 4506 sec 4.9) ---

    #[test]
    fn fixed_opaque_4_no_padding() {
        // RFC 4506 sec 4.9: N=4 is already aligned, no pad bytes needed.
        let data: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut buf = Vec::new();
        let written = data.pack(&mut buf).unwrap();
        assert_eq!(written, 4);
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);
        let (decoded, read) = <[u8; 4]>::unpack(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(read, 4);
    }

    #[test]
    fn fixed_opaque_3_pads_to_4() {
        // RFC 4506 sec 4.9: "padded with 0 to 3 residual zero bytes"
        let data: [u8; 3] = [0xAA, 0xBB, 0xCC];
        let mut buf = Vec::new();
        let written = data.pack(&mut buf).unwrap();
        assert_eq!(written, 4); // 3 data + 1 pad
        assert_eq!(buf, [0xAA, 0xBB, 0xCC, 0x00]);
        let (decoded, read) = <[u8; 3]>::unpack(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(read, 4);
    }

    #[test]
    fn fixed_opaque_5_pads_to_8() {
        // RFC 4506 sec 4.9: 5 bytes -> 3 bytes padding -> 8 total.
        let data: [u8; 5] = [1, 2, 3, 4, 5];
        let mut buf = Vec::new();
        let written = data.pack(&mut buf).unwrap();
        assert_eq!(written, 8);
        assert_eq!(buf, [1, 2, 3, 4, 5, 0, 0, 0]);
        let (decoded, read) = <[u8; 5]>::unpack(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, data);
        assert_eq!(read, 8);
    }

    #[test]
    fn fixed_opaque_1_packed_size_is_4() {
        // RFC 4506 sec 4.9: 1 byte rounds up to 4.
        let data: [u8; 1] = [0xFF];
        assert_eq!(data.packed_size(), 4);
    }

    #[test]
    fn fixed_opaque_8_packed_size_is_8() {
        let data: [u8; 8] = [0; 8];
        assert_eq!(data.packed_size(), 8);
    }

    // --- Vec<u32> (RFC 4506 sec 4.13: variable-length array) ---

    #[test]
    fn vec_u32_empty_round_trip() {
        // RFC 4506 sec 4.13: length prefix = 0, no elements.
        let v: Vec<u32> = vec![];
        let mut buf = Vec::new();
        let written = v.pack(&mut buf).unwrap();
        assert_eq!(written, 4); // just the length prefix
        assert_eq!(buf, [0, 0, 0, 0]);
        let (decoded, read) = Vec::<u32>::unpack(&mut buf.as_slice()).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(read, 4);
    }

    #[test]
    fn vec_u32_multiple_elements_round_trip() {
        let v: Vec<u32> = vec![100, 200, 300];
        let mut buf = Vec::new();
        let written = v.pack(&mut buf).unwrap();
        assert_eq!(written, 4 + 3 * 4); // length + 3 elements
        let (decoded, read) = Vec::<u32>::unpack(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, v);
        assert_eq!(read, written);
    }

    #[test]
    fn vec_u32_packed_size_matches_written() {
        let v: Vec<u32> = vec![1, 2, 3, 4, 5];
        let mut buf = Vec::new();
        let written = v.pack(&mut buf).unwrap();
        assert_eq!(v.packed_size(), written);
    }

    #[test]
    fn vec_u32_forged_length_does_not_oom() {
        // A forged count of 0xFFFFFFFF must not allocate 16 GiB.
        // vec_with_capacity caps at PREALLOC_CAP, and the subsequent reads
        // will fail with UnexpectedEof on the short body.
        let mut buf = Vec::new();
        let _ = 0xFFFF_FFFFu32.pack(&mut buf).unwrap(); // forged length
        buf.extend_from_slice(&[0; 8]); // only 2 elements worth of data
        let err = Vec::<u32>::unpack(&mut buf.as_slice());
        assert!(err.is_err());
    }

    // --- Golden vector: Vec<u32> (RFC 4506 sec 4.13) ---

    #[test]
    fn golden_vec_u32_two_elements() {
        // Hand-constructed wire bytes for Vec<u32> containing [0x100, 0x200]:
        //   count(4) = 2, elem0(4) = 0x100, elem1(4) = 0x200
        #[rustfmt::skip]
        const GOLDEN: [u8; 12] = [
            0x00, 0x00, 0x00, 0x02, // count = 2
            0x00, 0x00, 0x01, 0x00, // element 0 = 256
            0x00, 0x00, 0x02, 0x00, // element 1 = 512
        ];

        let (decoded, consumed) = Vec::<u32>::unpack(&mut &GOLDEN[..]).unwrap();
        assert_eq!(consumed, GOLDEN.len());
        assert_eq!(decoded, vec![0x100, 0x200]);

        let mut repacked = Vec::new();
        let _ = decoded.pack(&mut repacked).unwrap();
        assert_eq!(repacked, GOLDEN);
    }

    // --- Golden vector: bool (RFC 4506 sec 4.4) ---

    #[test]
    fn golden_bool_true_false() {
        // RFC 4506 sec 4.4: bool = enum { FALSE = 0, TRUE = 1 }, 4 bytes.
        const TRUE_WIRE: [u8; 4] = [0x00, 0x00, 0x00, 0x01];
        const FALSE_WIRE: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

        let (t, _) = bool::unpack(&mut &TRUE_WIRE[..]).unwrap();
        assert!(t);
        let (f, _) = bool::unpack(&mut &FALSE_WIRE[..]).unwrap();
        assert!(!f);

        let mut buf = Vec::new();
        let _ = true.pack(&mut buf).unwrap();
        assert_eq!(buf, TRUE_WIRE);
        buf.clear();
        let _ = false.pack(&mut buf).unwrap();
        assert_eq!(buf, FALSE_WIRE);
    }
}
