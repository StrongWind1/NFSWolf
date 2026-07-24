//! Padding arithmetic for XDR's 4-byte alignment rule.
//!
//! RFC 4506 sec. 3 requires every XDR item to occupy a multiple of four bytes,
//! with the remainder zero-filled.  Getting this wrong desynchronises the
//! whole stream, so the three helpers here are used by every variable-length
//! type in the crate rather than open-coding the arithmetic at each site.

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
}
