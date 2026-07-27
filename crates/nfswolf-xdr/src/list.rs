use std::io::{Read, Write};

use crate::{Pack, Unpack};

/// Represents a sequence of optional values in NFS3.
///
/// This struct is a wrapper around a `Vec<T>`, where `T` is a type that implements
/// the [`Pack`] and [`Unpack`] traits for serialization and deserialization.
#[derive(Debug)]
pub struct List<T>(pub Vec<T>);

impl<T> Default for List<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> List<T> {
    /// Consumes the list and returns the underlying `Vec`.
    #[must_use]
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }

    /// Returns true when the list holds no elements.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T> Pack for List<T>
where
    T: Pack,
{
    fn packed_size(&self) -> usize {
        let mut len = 0;
        for item in &self.0 {
            len += <bool as Pack>::packed_size(&true);
            len += item.packed_size();
        }
        len += <bool as Pack>::packed_size(&false);
        len
    }

    fn pack(&self, out: &mut impl Write) -> crate::Result<usize> {
        let mut len = 0;
        for item in &self.0 {
            len += true.pack(out)?;
            len += item.pack(out)?;
        }
        len += false.pack(out)?;
        Ok(len)
    }
}

impl<T> Unpack for List<T>
where
    T: Unpack,
{
    fn unpack(input: &mut impl Read) -> crate::Result<(Self, usize)> {
        let mut items = Vec::new();
        let mut len = 0;
        loop {
            let (more, more_len) = bool::unpack(input)?;
            len += more_len;
            if !more {
                break;
            }
            let (item, item_len) = T::unpack(input)?;
            len += item_len;
            items.push(item);
        }
        Ok((Self(items), len))
    }
}

/// A [`List`] that refuses elements once its encoded size would exceed a cap.
///
/// NFS replies are bounded by a byte count the client asks for, not an element
/// count -- `READDIR` takes a `maxcount` in bytes.  Tracking the packed size as
/// elements are added is the only way to fill such a reply without overshooting.
#[derive(Debug)]
pub struct BoundedList<T> {
    list: List<T>,
    current_size: usize,
    max_size: usize,
}

impl<T> BoundedList<T>
where
    T: Pack,
{
    /// Creates an empty list that will not exceed `max_size` bytes when packed.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        let list = List(Vec::new());
        let current_size = <List<T> as Pack>::packed_size(&list);
        Self { list, current_size, max_size }
    }

    /// Appends an item, returning it back unchanged if it would not fit.
    pub fn try_push(&mut self, item: T) -> Result<(), T> {
        let item_size = item.packed_size() + 4;
        if self.current_size + item_size > self.max_size {
            return Err(item);
        }

        self.list.0.push(item);
        self.current_size += item_size;
        Ok(())
    }

    /// Consumes the bounded list and returns the accumulated [`List`].
    #[must_use]
    pub fn into_inner(self) -> List<T> {
        self.list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- List (RFC 4506 sec 4.11: optional-data / linked-list encoding) ---

    #[test]
    fn list_empty_round_trip() {
        // An empty list is a single FALSE discriminant (4 bytes of zeroes).
        let list: List<u32> = List(vec![]);
        let mut buf = Vec::new();
        let written = list.pack(&mut buf).unwrap();
        assert_eq!(written, 4); // one bool discriminant = FALSE
        assert_eq!(buf, [0, 0, 0, 0]);
        let (decoded, read) = List::<u32>::unpack(&mut buf.as_slice()).unwrap();
        assert!(decoded.0.is_empty());
        assert_eq!(read, 4);
    }

    #[test]
    fn list_single_element_round_trip() {
        // TRUE + element + FALSE terminator.
        let list: List<u32> = List(vec![42]);
        let mut buf = Vec::new();
        let written = list.pack(&mut buf).unwrap();
        // 4 (TRUE) + 4 (element) + 4 (FALSE) = 12
        assert_eq!(written, 12);
        let (decoded, read) = List::<u32>::unpack(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.0, vec![42]);
        assert_eq!(read, 12);
    }

    #[test]
    fn list_multiple_elements_round_trip() {
        let list: List<u32> = List(vec![10, 20, 30]);
        let mut buf = Vec::new();
        let written = list.pack(&mut buf).unwrap();
        // 3 * (4 TRUE + 4 element) + 4 FALSE = 28
        assert_eq!(written, 28);
        let (decoded, read) = List::<u32>::unpack(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.0, vec![10, 20, 30]);
        assert_eq!(read, 28);
    }

    #[test]
    fn list_packed_size_matches_actual_written() {
        let list: List<u32> = List(vec![1, 2, 3, 4, 5]);
        let mut buf = Vec::new();
        let written = list.pack(&mut buf).unwrap();
        assert_eq!(list.packed_size(), written);
    }

    // --- BoundedList ---

    #[test]
    fn bounded_list_rejects_overflow() {
        // A BoundedList with max_size=12 can fit exactly one u32 element:
        //   empty list = 4 bytes (FALSE terminator)
        //   one element = 4 (TRUE) + 4 (u32) = 8 more -> 12 total
        // A second element would need 8 more bytes -> 20 > 12.
        let mut bl = BoundedList::<u32>::new(12);
        assert!(bl.try_push(1).is_ok());
        let rejected = bl.try_push(2);
        assert!(rejected.is_err());
        assert_eq!(rejected.unwrap_err(), 2); // returns the item back
    }

    #[test]
    fn bounded_list_converts_to_list() {
        let mut bl = BoundedList::<u32>::new(1024);
        bl.try_push(100).unwrap();
        bl.try_push(200).unwrap();
        let list = bl.into_inner();
        assert_eq!(list.0, vec![100, 200]);
    }
}
