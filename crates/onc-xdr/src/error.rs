use std::fmt;

/// Something went wrong encoding to or decoding from the XDR wire format.
///
/// Decode failures are routine when probing hostile or non-conforming servers,
/// so these carry enough detail to tell a malformed reply from a transport
/// fault: `Io` means the socket failed, everything else means the peer sent
/// bytes that do not parse as the expected type.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An error occurred while reading or writing data.
    Io(std::io::Error),

    /// An invalid value was encountered for an enum/bool type.
    InvalidEnumValue(u32),

    /// An error occurred while unpacking an object.
    InvalidLength(usize),

    /// An error occurred while packing an object.
    ObjectTooLarge(usize),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidEnumValue(value) => write!(f, "Invalid enum value: {value}"),
            Self::InvalidLength(len) => write!(f, "Invalid length: {len}"),
            Self::ObjectTooLarge(size) => write!(f, "Object too large: {size} bytes"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}
