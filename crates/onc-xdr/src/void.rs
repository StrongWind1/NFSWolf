use super::{Error, Pack, Unpack};

/// The XDR "void" type -- zero bytes on the wire.
///
/// Used as the argument type of procedures that take nothing and as the
/// result type of those that return nothing.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Void;

impl Pack for Void {
    fn packed_size(&self) -> usize {
        0
    }

    fn pack(&self, _out: &mut impl std::io::Write) -> Result<usize, Error> {
        Ok(0)
    }
}

impl Unpack for Void {
    fn unpack(_input: &mut impl std::io::Read) -> Result<(Self, usize), Error> {
        Ok((Self, 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn void_packed_size_is_zero() {
        // XDR void occupies zero bytes on the wire.
        assert_eq!(Void.packed_size(), 0);
    }

    #[test]
    fn void_pack_writes_nothing() {
        let mut buf = Vec::new();
        let written = Void.pack(&mut buf).unwrap();
        assert_eq!(written, 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn void_unpack_consumes_nothing() {
        let data: &[u8] = &[0xFF, 0xFF]; // junk -- Void should not touch it
        let (v, read) = Void::unpack(&mut &data[..]).unwrap();
        assert_eq!(v, Void);
        assert_eq!(read, 0);
    }
}
