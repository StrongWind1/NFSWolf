#![expect(non_camel_case_types, clippy::upper_case_acronyms, reason = "identifiers are transcribed verbatim from the RFC's XDR definitions; renaming them to Rust conventions would break the correspondence a reader needs when checking this module against the spec")]
#![expect(missing_docs, reason = "these are mechanical transcriptions of the RFC's XDR type table -- per-field prose would restate the field name and nothing more. The module doc cites the defining RFC section, which is the real documentation")]
#![expect(
    missing_copy_implementations,
    reason = "Copy is derived on the wire types whose callers benefit from it; demanding it exhaustively cascades through every containing struct without improving the API, and whether a value is copied or moved is a Rust-side choice the wire format has no opinion on"
)]
#![expect(single_use_lifetimes, reason = "newtype wrappers over Opaque<'a> genuinely need the parameter; the lint counts the declaration and the single use and misreads it as removable")]

//! This module contains the definitions of the `NFSv3` protocol as defined in RFC 1813.

use std::io::{Read, Write};

use onc_xdr::XdrCodec;

use onc_xdr::{List, Opaque, Pack, Unpack, Void};

pub const PROGRAM: u32 = 100_003;
pub const VERSION: u32 = 3;

pub const ACCESS3_READ: u32 = 1;
pub const ACCESS3_LOOKUP: u32 = 2;
pub const ACCESS3_MODIFY: u32 = 4;
pub const ACCESS3_EXTEND: u32 = 8;
pub const ACCESS3_DELETE: u32 = 16;
pub const ACCESS3_EXECUTE: u32 = 32;

pub const FSF3_LINK: u32 = 1;
pub const FSF3_SYMLINK: u32 = 2;
pub const FSF3_HOMOGENEOUS: u32 = 8;
pub const FSF3_CANSETTIME: u32 = 16;

pub const NFS3_COOKIEVERFSIZE: usize = 8;
pub const NFS3_CREATEVERFSIZE: usize = 8;
pub const NFS3_FHSIZE: usize = 64;
pub const NFS3_WRITEVERFSIZE: usize = 8;

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Nfs3Result<T, E> {
    Ok(T),
    Err((nfsstat3, E)),
}

impl<T, E: std::fmt::Debug> Nfs3Result<T, E> {
    /// Returns the contained value, consuming the result.
    ///
    /// # Panics
    ///
    /// Panics if the result is an `Err`.
    #[expect(clippy::panic, reason = "panicking accessor mirroring Option::unwrap; the # Panics section documents it and callers who cannot panic match on the result instead")]
    pub fn unwrap(self) -> T {
        match self {
            Self::Ok(val) => val,
            Self::Err((code, res)) => panic!("NFS3 error: {code:?}, result: {res:?}"),
        }
    }

    /// Returns the contained value, consuming the result.
    ///
    /// # Panics
    ///
    /// Panics if the result is an `Err`, with a custom panic message.
    #[expect(clippy::panic, reason = "panicking accessor mirroring Option::expect; the # Panics section documents it")]
    pub fn expect(self, msg: &str) -> T {
        match self {
            Self::Ok(val) => val,
            Self::Err((code, res)) => panic!("{msg}: NFS3 error: {code:?}, result: {res:?}"),
        }
    }
}

impl<T, E> Pack for Nfs3Result<T, E>
where
    T: Pack,
    E: Pack,
{
    fn packed_size(&self) -> usize {
        match self {
            Self::Ok(v) => nfsstat3::NFS3_OK.packed_size() + v.packed_size(),
            Self::Err((code, err)) => code.packed_size() + err.packed_size(),
        }
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        let len = match self {
            Self::Ok(v) => nfsstat3::NFS3_OK.pack(out)? + v.pack(out)?,
            Self::Err((code, err)) => code.pack(out)? + err.pack(out)?,
        };
        Ok(len)
    }
}

impl<T, E> Unpack for Nfs3Result<T, E>
where
    T: Unpack,
    E: Unpack,
{
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let mut sz = 0;
        let (code, dsz): (nfsstat3, usize) = Unpack::unpack(input)?;
        sz += dsz;
        if code == nfsstat3::NFS3_OK {
            let (val, fsz) = Unpack::unpack(input)?;
            sz += fsz;
            Ok((Self::Ok(val), sz))
        } else {
            let (val, csz) = Unpack::unpack(input)?;
            sz += csz;
            Ok((Self::Err((code, val)), sz))
        }
    }
}

pub type ACCESS3res = Nfs3Result<ACCESS3resok, ACCESS3resfail>;
pub type COMMIT3res = Nfs3Result<COMMIT3resok, COMMIT3resfail>;
pub type CREATE3res = Nfs3Result<CREATE3resok, CREATE3resfail>;
pub type FSINFO3res = Nfs3Result<FSINFO3resok, FSINFO3resfail>;
pub type FSSTAT3res = Nfs3Result<FSSTAT3resok, FSSTAT3resfail>;
pub type GETATTR3res = Nfs3Result<GETATTR3resok, Void>;
pub type LINK3res = Nfs3Result<LINK3resok, LINK3resfail>;
pub type LOOKUP3res = Nfs3Result<LOOKUP3resok, LOOKUP3resfail>;
pub type MKDIR3res = Nfs3Result<MKDIR3resok, MKDIR3resfail>;
pub type MKNOD3res = Nfs3Result<MKNOD3resok, MKNOD3resfail>;
pub type PATHCONF3res = Nfs3Result<PATHCONF3resok, PATHCONF3resfail>;
pub type READ3res<'a> = Nfs3Result<READ3resok<'a>, READ3resfail>;
pub type READDIR3res<'a> = Nfs3Result<READDIR3resok<'a>, READDIR3resfail>;
pub type READDIRPLUS3res<'a> = Nfs3Result<READDIRPLUS3resok<'a>, READDIRPLUS3resfail>;
pub type READLINK3res<'a> = Nfs3Result<READLINK3resok<'a>, READLINK3resfail>;
pub type REMOVE3res = Nfs3Result<REMOVE3resok, REMOVE3resfail>;
pub type RENAME3res = Nfs3Result<RENAME3resok, RENAME3resfail>;
pub type RMDIR3res = Nfs3Result<RMDIR3resok, RMDIR3resfail>;
pub type SETATTR3res = Nfs3Result<SETATTR3resok, SETATTR3resfail>;
pub type SYMLINK3res = Nfs3Result<SYMLINK3resok, SYMLINK3resfail>;
pub type WRITE3res = Nfs3Result<WRITE3resok, WRITE3resfail>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, XdrCodec)]
#[non_exhaustive]
pub enum Nfs3Option<T: Pack + Unpack> {
    #[xdr(1)]
    Some(T),
    #[default]
    #[xdr(0)]
    None,
}

impl<T: Pack + Unpack> Nfs3Option<T> {
    pub const fn is_some(&self) -> bool {
        matches!(self, Self::Some(_))
    }
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Returns the contained value, consuming the option.
    ///
    /// # Panics
    ///
    /// Panics if the option is `None`.
    #[expect(clippy::panic, reason = "panicking accessor mirroring Option::unwrap; the # Panics section documents it")]
    pub fn unwrap(self) -> T {
        match self {
            Self::Some(val) => val,
            Self::None => panic!("called `Nfs3Option::unwrap()` on a `None` value"),
        }
    }
}

pub type pre_op_attr = Nfs3Option<wcc_attr>;
pub type post_op_attr = Nfs3Option<fattr3>;
pub type post_op_fh3 = Nfs3Option<nfs_fh3>;
pub type sattrguard3 = Nfs3Option<nfstime3>;
pub type set_gid3 = Nfs3Option<gid3>;
pub type set_mode3 = Nfs3Option<mode3>;
pub type set_size3 = Nfs3Option<size3>;
pub type set_uid3 = Nfs3Option<uid3>;

#[derive(Debug, XdrCodec)]
pub struct ACCESS3args {
    pub object: nfs_fh3,
    pub access: u32,
}

#[derive(Debug, Default, XdrCodec)]
pub struct ACCESS3resfail {
    pub obj_attributes: post_op_attr,
}

#[derive(Debug, XdrCodec)]
pub struct ACCESS3resok {
    pub obj_attributes: post_op_attr,
    pub access: u32,
}

#[derive(Debug, XdrCodec)]
pub struct COMMIT3args {
    pub file: nfs_fh3,
    pub offset: offset3,
    pub count: count3,
}

#[derive(Debug, XdrCodec)]
pub struct COMMIT3resfail {
    pub file_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct COMMIT3resok {
    pub file_wcc: wcc_data,
    pub verf: writeverf3,
}

#[derive(Debug, XdrCodec)]
pub struct CREATE3args<'a> {
    pub where_: diropargs3<'a>,
    pub how: createhow3,
}

#[derive(Debug, Default, XdrCodec)]
pub struct CREATE3resfail {
    pub dir_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct CREATE3resok {
    pub obj: post_op_fh3,
    pub obj_attributes: post_op_attr,
    pub dir_wcc: wcc_data,
}

#[derive(Clone, Debug, Eq, PartialEq, XdrCodec)]
pub struct FSINFO3args {
    pub fsroot: nfs_fh3,
}

impl From<nfs_fh3> for FSINFO3args {
    fn from(fh: nfs_fh3) -> Self {
        Self { fsroot: fh }
    }
}

#[derive(Debug, Default, XdrCodec)]
pub struct FSINFO3resfail {
    pub obj_attributes: post_op_attr,
}

#[derive(Debug, XdrCodec)]
pub struct FSINFO3resok {
    pub obj_attributes: post_op_attr,
    pub rtmax: u32,
    pub rtpref: u32,
    pub rtmult: u32,
    pub wtmax: u32,
    pub wtpref: u32,
    pub wtmult: u32,
    pub dtpref: u32,
    pub maxfilesize: size3,
    pub time_delta: nfstime3,
    pub properties: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, XdrCodec)]
pub struct FSSTAT3args {
    pub fsroot: nfs_fh3,
}

impl From<nfs_fh3> for FSSTAT3args {
    fn from(fh: nfs_fh3) -> Self {
        Self { fsroot: fh }
    }
}

#[derive(Debug, Default, XdrCodec)]
pub struct FSSTAT3resfail {
    pub obj_attributes: post_op_attr,
}

#[derive(Debug, XdrCodec)]
pub struct FSSTAT3resok {
    pub obj_attributes: post_op_attr,
    pub tbytes: size3,
    pub fbytes: size3,
    pub abytes: size3,
    pub tfiles: size3,
    pub ffiles: size3,
    pub afiles: size3,
    pub invarsec: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, XdrCodec)]
pub struct GETATTR3args {
    pub object: nfs_fh3,
}

impl From<nfs_fh3> for GETATTR3args {
    fn from(fh: nfs_fh3) -> Self {
        Self { object: fh }
    }
}

#[derive(Debug, XdrCodec)]
pub struct GETATTR3resok {
    pub obj_attributes: fattr3,
}

#[derive(Debug, Eq, PartialEq, XdrCodec)]
pub struct LINK3args<'a> {
    pub file: nfs_fh3,
    pub link: diropargs3<'a>,
}

#[derive(Debug, XdrCodec)]
pub struct LINK3resfail {
    pub file_attributes: post_op_attr,
    pub linkdir_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct LINK3resok {
    pub file_attributes: post_op_attr,
    pub linkdir_wcc: wcc_data,
}

#[derive(Debug, Eq, PartialEq, XdrCodec)]
pub struct LOOKUP3args<'a> {
    pub what: diropargs3<'a>,
}

#[derive(Debug, Default, XdrCodec)]
pub struct LOOKUP3resfail {
    pub dir_attributes: post_op_attr,
}

#[derive(Debug, XdrCodec)]
pub struct LOOKUP3resok {
    pub object: nfs_fh3,
    pub obj_attributes: post_op_attr,
    pub dir_attributes: post_op_attr,
}

#[derive(Debug, XdrCodec)]
pub struct MKDIR3args<'a> {
    pub where_: diropargs3<'a>,
    pub attributes: sattr3,
}

#[derive(Debug, Default, XdrCodec)]
pub struct MKDIR3resfail {
    pub dir_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct MKDIR3resok {
    pub obj: post_op_fh3,
    pub obj_attributes: post_op_attr,
    pub dir_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct MKNOD3args<'a> {
    pub where_: diropargs3<'a>,
    pub what: mknoddata3,
}

#[derive(Debug, XdrCodec)]
pub struct MKNOD3resfail {
    pub dir_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct MKNOD3resok {
    pub obj: post_op_fh3,
    pub obj_attributes: post_op_attr,
    pub dir_wcc: wcc_data,
}

#[derive(Clone, Debug, Eq, PartialEq, XdrCodec)]
pub struct PATHCONF3args {
    pub object: nfs_fh3,
}

impl From<nfs_fh3> for PATHCONF3args {
    fn from(fh: nfs_fh3) -> Self {
        Self { object: fh }
    }
}

#[derive(Debug, Default, XdrCodec)]
pub struct PATHCONF3resfail {
    pub obj_attributes: post_op_attr,
}

#[derive(Debug, XdrCodec)]
pub struct PATHCONF3resok {
    pub obj_attributes: post_op_attr,
    pub linkmax: u32,
    pub name_max: u32,
    pub no_trunc: bool,
    pub chown_restricted: bool,
    pub case_insensitive: bool,
    pub case_preserving: bool,
}

#[derive(Debug, XdrCodec)]
pub struct READ3args {
    pub file: nfs_fh3,
    pub offset: offset3,
    pub count: count3,
}

#[derive(Debug, Default, XdrCodec)]
pub struct READ3resfail {
    pub file_attributes: post_op_attr,
}

#[derive(Debug, XdrCodec)]
pub struct READ3resok<'a> {
    pub file_attributes: post_op_attr,
    pub count: count3,
    pub eof: bool,
    pub data: Opaque<'a>,
}

#[derive(Debug, XdrCodec)]
pub struct READDIR3args {
    pub dir: nfs_fh3,
    pub cookie: cookie3,
    pub cookieverf: cookieverf3,
    pub count: count3,
}

#[derive(Debug, Default, XdrCodec)]
pub struct READDIR3resfail {
    pub dir_attributes: post_op_attr,
}

#[derive(Debug, XdrCodec)]
pub struct READDIR3resok<'a> {
    pub dir_attributes: post_op_attr,
    pub cookieverf: cookieverf3,
    pub reply: dirlist3<'a>,
}

#[derive(Debug, XdrCodec)]
pub struct READDIRPLUS3args {
    pub dir: nfs_fh3,
    pub cookie: cookie3,
    pub cookieverf: cookieverf3,
    pub dircount: count3,
    pub maxcount: count3,
}

#[derive(Default, Debug, XdrCodec)]
pub struct READDIRPLUS3resfail {
    pub dir_attributes: post_op_attr,
}

#[derive(Debug, XdrCodec)]
pub struct READDIRPLUS3resok<'a> {
    pub dir_attributes: post_op_attr,
    pub cookieverf: cookieverf3,
    pub reply: dirlistplus3<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq, XdrCodec)]
pub struct READLINK3args {
    pub symlink: nfs_fh3,
}

#[derive(Default, Debug, XdrCodec)]
pub struct READLINK3resfail {
    pub symlink_attributes: post_op_attr,
}

#[derive(Debug, XdrCodec)]
pub struct READLINK3resok<'a> {
    pub symlink_attributes: post_op_attr,
    pub data: nfspath3<'a>,
}

#[derive(Debug, Eq, PartialEq, XdrCodec)]
pub struct REMOVE3args<'a> {
    pub object: diropargs3<'a>,
}

#[derive(Debug, Default, XdrCodec)]
pub struct REMOVE3resfail {
    pub dir_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct REMOVE3resok {
    pub dir_wcc: wcc_data,
}

#[derive(Debug, Eq, PartialEq, XdrCodec)]
pub struct RENAME3args<'a, 'b> {
    pub from: diropargs3<'a>,
    pub to: diropargs3<'b>,
}

#[derive(Debug, Default, XdrCodec)]
pub struct RENAME3resfail {
    pub fromdir_wcc: wcc_data,
    pub todir_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct RENAME3resok {
    pub fromdir_wcc: wcc_data,
    pub todir_wcc: wcc_data,
}

#[derive(Debug, Eq, PartialEq, XdrCodec)]
pub struct RMDIR3args<'a> {
    pub object: diropargs3<'a>,
}

#[derive(Debug, XdrCodec)]
pub struct RMDIR3resfail {
    pub dir_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct RMDIR3resok {
    pub dir_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct SETATTR3args {
    pub object: nfs_fh3,
    pub new_attributes: sattr3,
    pub guard: sattrguard3,
}

#[derive(Debug, Default, XdrCodec)]
pub struct SETATTR3resfail {
    pub obj_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct SETATTR3resok {
    pub obj_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct SYMLINK3args<'a> {
    pub where_: diropargs3<'a>,
    pub symlink: symlinkdata3<'a>,
}

#[derive(Debug, Default, XdrCodec)]
pub struct SYMLINK3resfail {
    pub dir_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct SYMLINK3resok {
    pub obj: post_op_fh3,
    pub obj_attributes: post_op_attr,
    pub dir_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct WRITE3args<'a> {
    pub file: nfs_fh3,
    pub offset: offset3,
    pub count: count3,
    pub stable: stable_how,
    pub data: Opaque<'a>,
}

#[derive(Debug, Default, XdrCodec)]
pub struct WRITE3resfail {
    pub file_wcc: wcc_data,
}

#[derive(Debug, XdrCodec)]
pub struct WRITE3resok {
    pub file_wcc: wcc_data,
    pub count: count3,
    pub committed: stable_how,
    pub verf: writeverf3,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, XdrCodec)]
pub struct cookieverf3(pub [u8; NFS3_COOKIEVERFSIZE]);

#[derive(Debug, XdrCodec)]
#[non_exhaustive]
pub enum createhow3 {
    #[xdr(0)]
    UNCHECKED(sattr3),
    #[xdr(1)]
    GUARDED(sattr3),
    #[xdr(2)]
    EXCLUSIVE(createverf3),
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, XdrCodec)]
#[non_exhaustive]
pub enum createmode3 {
    #[default]
    UNCHECKED = 0,
    GUARDED = 1,
    EXCLUSIVE = 2,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, XdrCodec)]
pub struct createverf3(pub [u8; NFS3_CREATEVERFSIZE]);

#[derive(Debug, XdrCodec)]
pub struct devicedata3 {
    pub dev_attributes: sattr3,
    pub spec: specdata3,
}

#[derive(Debug, Default, XdrCodec)]
pub struct dirlist3<'a> {
    pub entries: List<entry3<'a>>,
    pub eof: bool,
}

#[derive(Debug, XdrCodec)]
pub struct dirlistplus3<'a> {
    pub entries: List<entryplus3<'a>>,
    pub eof: bool,
}

#[derive(Debug, Eq, PartialEq, XdrCodec)]
pub struct diropargs3<'a> {
    pub dir: nfs_fh3,
    pub name: filename3<'a>,
}

#[derive(Debug, Clone, XdrCodec, PartialEq, Eq)]
pub struct entry3<'a> {
    pub fileid: fileid3,
    pub name: filename3<'a>,
    pub cookie: cookie3,
}

#[derive(Debug, XdrCodec)]
pub struct entryplus3<'a> {
    pub fileid: fileid3,
    pub name: filename3<'a>,
    pub cookie: cookie3,
    pub name_attributes: post_op_attr,
    pub name_handle: post_op_fh3,
}

#[derive(Debug, Clone, XdrCodec)]
pub struct fattr3 {
    pub type_: ftype3,
    pub mode: mode3,
    pub nlink: u32,
    pub uid: uid3,
    pub gid: gid3,
    pub size: size3,
    pub used: size3,
    pub rdev: specdata3,
    pub fsid: u64,
    pub fileid: fileid3,
    pub atime: nfstime3,
    pub mtime: nfstime3,
    pub ctime: nfstime3,
}

#[derive(Debug, Clone, Eq, PartialEq, XdrCodec)]
pub struct filename3<'a>(pub Opaque<'a>);

impl From<Vec<u8>> for filename3<'static> {
    fn from(name: Vec<u8>) -> Self {
        Self(Opaque::owned(name))
    }
}

impl<'a> From<&'a [u8]> for filename3<'a> {
    fn from(name: &'a [u8]) -> Self {
        Self(Opaque::borrowed(name))
    }
}

impl AsRef<[u8]> for filename3<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl filename3<'_> {
    #[must_use]
    pub fn clone_to_owned(&self) -> filename3<'static> {
        self.0.to_vec().into()
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl PartialEq<[u8]> for filename3<'_> {
    fn eq(&self, other: &[u8]) -> bool {
        self.0.as_ref() == other
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, XdrCodec)]
#[non_exhaustive]
pub enum ftype3 {
    #[default]
    NF3REG = 1,
    NF3DIR = 2,
    NF3BLK = 3,
    NF3CHR = 4,
    NF3LNK = 5,
    NF3SOCK = 6,
    NF3FIFO = 7,
}

impl std::fmt::Display for ftype3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::NF3REG => "NF3REG",
            Self::NF3DIR => "NF3DIR",
            Self::NF3BLK => "NF3BLK",
            Self::NF3CHR => "NF3CHR",
            Self::NF3LNK => "NF3LNK",
            Self::NF3SOCK => "NF3SOCK",
            Self::NF3FIFO => "NF3FIFO",
        };
        std::fmt::Display::fmt(name, f)
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum mknoddata3 {
    NF3CHR(devicedata3),
    NF3BLK(devicedata3),
    NF3SOCK(sattr3),
    NF3FIFO(sattr3),
    default,
}

#[derive(Clone, Debug, Eq, PartialEq, XdrCodec)]
pub struct nfs_fh3 {
    pub data: Opaque<'static>,
}

impl Default for nfs_fh3 {
    fn default() -> Self {
        Self { data: Opaque::borrowed(&[]) }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, XdrCodec)]
pub struct nfspath3<'a>(pub Opaque<'a>);

impl From<Vec<u8>> for nfspath3<'static> {
    fn from(name: Vec<u8>) -> Self {
        Self(Opaque::owned(name))
    }
}

impl<'a> From<&'a [u8]> for nfspath3<'a> {
    fn from(name: &'a [u8]) -> Self {
        Self(Opaque::borrowed(name))
    }
}

impl AsRef<[u8]> for nfspath3<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl nfspath3<'_> {
    #[must_use]
    pub fn clone_to_owned(&self) -> nfspath3<'static> {
        self.0.to_vec().into()
    }
    #[must_use]
    pub fn into_owned(self) -> nfspath3<'static> {
        nfspath3(Opaque::owned(self.0.into_owned()))
    }
}

impl PartialEq<[u8]> for nfspath3<'_> {
    fn eq(&self, other: &[u8]) -> bool {
        self.0.as_ref() == other
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum nfsstat3 {
    #[default]
    NFS3_OK,
    NFS3ERR_PERM,
    NFS3ERR_NOENT,
    NFS3ERR_IO,
    NFS3ERR_NXIO,
    NFS3ERR_ACCES,
    NFS3ERR_EXIST,
    NFS3ERR_XDEV,
    NFS3ERR_NODEV,
    NFS3ERR_NOTDIR,
    NFS3ERR_ISDIR,
    NFS3ERR_INVAL,
    NFS3ERR_FBIG,
    NFS3ERR_NOSPC,
    NFS3ERR_ROFS,
    NFS3ERR_MLINK,
    NFS3ERR_NAMETOOLONG,
    NFS3ERR_NOTEMPTY,
    NFS3ERR_DQUOT,
    NFS3ERR_STALE,
    NFS3ERR_REMOTE,
    NFS3ERR_BADHANDLE,
    NFS3ERR_NOT_SYNC,
    NFS3ERR_BAD_COOKIE,
    NFS3ERR_NOTSUPP,
    NFS3ERR_TOOSMALL,
    NFS3ERR_SERVERFAULT,
    NFS3ERR_BADTYPE,
    NFS3ERR_JUKEBOX,
    Unknown(u32),
}

impl nfsstat3 {
    const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::NFS3_OK,
            1 => Self::NFS3ERR_PERM,
            2 => Self::NFS3ERR_NOENT,
            5 => Self::NFS3ERR_IO,
            6 => Self::NFS3ERR_NXIO,
            13 => Self::NFS3ERR_ACCES,
            17 => Self::NFS3ERR_EXIST,
            18 => Self::NFS3ERR_XDEV,
            19 => Self::NFS3ERR_NODEV,
            20 => Self::NFS3ERR_NOTDIR,
            21 => Self::NFS3ERR_ISDIR,
            22 => Self::NFS3ERR_INVAL,
            27 => Self::NFS3ERR_FBIG,
            28 => Self::NFS3ERR_NOSPC,
            30 => Self::NFS3ERR_ROFS,
            31 => Self::NFS3ERR_MLINK,
            63 => Self::NFS3ERR_NAMETOOLONG,
            66 => Self::NFS3ERR_NOTEMPTY,
            69 => Self::NFS3ERR_DQUOT,
            70 => Self::NFS3ERR_STALE,
            71 => Self::NFS3ERR_REMOTE,
            10001 => Self::NFS3ERR_BADHANDLE,
            10002 => Self::NFS3ERR_NOT_SYNC,
            10003 => Self::NFS3ERR_BAD_COOKIE,
            10004 => Self::NFS3ERR_NOTSUPP,
            10005 => Self::NFS3ERR_TOOSMALL,
            10006 => Self::NFS3ERR_SERVERFAULT,
            10007 => Self::NFS3ERR_BADTYPE,
            10008 => Self::NFS3ERR_JUKEBOX,
            _ => Self::Unknown(v),
        }
    }

    const fn to_u32(self) -> u32 {
        match self {
            Self::NFS3_OK => 0,
            Self::NFS3ERR_PERM => 1,
            Self::NFS3ERR_NOENT => 2,
            Self::NFS3ERR_IO => 5,
            Self::NFS3ERR_NXIO => 6,
            Self::NFS3ERR_ACCES => 13,
            Self::NFS3ERR_EXIST => 17,
            Self::NFS3ERR_XDEV => 18,
            Self::NFS3ERR_NODEV => 19,
            Self::NFS3ERR_NOTDIR => 20,
            Self::NFS3ERR_ISDIR => 21,
            Self::NFS3ERR_INVAL => 22,
            Self::NFS3ERR_FBIG => 27,
            Self::NFS3ERR_NOSPC => 28,
            Self::NFS3ERR_ROFS => 30,
            Self::NFS3ERR_MLINK => 31,
            Self::NFS3ERR_NAMETOOLONG => 63,
            Self::NFS3ERR_NOTEMPTY => 66,
            Self::NFS3ERR_DQUOT => 69,
            Self::NFS3ERR_STALE => 70,
            Self::NFS3ERR_REMOTE => 71,
            Self::NFS3ERR_BADHANDLE => 10001,
            Self::NFS3ERR_NOT_SYNC => 10002,
            Self::NFS3ERR_BAD_COOKIE => 10003,
            Self::NFS3ERR_NOTSUPP => 10004,
            Self::NFS3ERR_TOOSMALL => 10005,
            Self::NFS3ERR_SERVERFAULT => 10006,
            Self::NFS3ERR_BADTYPE => 10007,
            Self::NFS3ERR_JUKEBOX => 10008,
            Self::Unknown(v) => v,
        }
    }
}

impl Pack for nfsstat3 {
    fn packed_size(&self) -> usize {
        4
    }
    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        self.to_u32().pack(out)
    }
}

impl Unpack for nfsstat3 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let (v, n) = u32::unpack(input)?;
        Ok((Self::from_u32(v), n))
    }
}

impl std::fmt::Display for nfsstat3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NFS3_OK => f.write_str("NFS3_OK"),
            Self::NFS3ERR_PERM => f.write_str("NFS3ERR_PERM"),
            Self::NFS3ERR_NOENT => f.write_str("NFS3ERR_NOENT"),
            Self::NFS3ERR_IO => f.write_str("NFS3ERR_IO"),
            Self::NFS3ERR_NXIO => f.write_str("NFS3ERR_NXIO"),
            Self::NFS3ERR_ACCES => f.write_str("NFS3ERR_ACCES"),
            Self::NFS3ERR_EXIST => f.write_str("NFS3ERR_EXIST"),
            Self::NFS3ERR_XDEV => f.write_str("NFS3ERR_XDEV"),
            Self::NFS3ERR_NODEV => f.write_str("NFS3ERR_NODEV"),
            Self::NFS3ERR_NOTDIR => f.write_str("NFS3ERR_NOTDIR"),
            Self::NFS3ERR_ISDIR => f.write_str("NFS3ERR_ISDIR"),
            Self::NFS3ERR_INVAL => f.write_str("NFS3ERR_INVAL"),
            Self::NFS3ERR_FBIG => f.write_str("NFS3ERR_FBIG"),
            Self::NFS3ERR_NOSPC => f.write_str("NFS3ERR_NOSPC"),
            Self::NFS3ERR_ROFS => f.write_str("NFS3ERR_ROFS"),
            Self::NFS3ERR_MLINK => f.write_str("NFS3ERR_MLINK"),
            Self::NFS3ERR_NAMETOOLONG => f.write_str("NFS3ERR_NAMETOOLONG"),
            Self::NFS3ERR_NOTEMPTY => f.write_str("NFS3ERR_NOTEMPTY"),
            Self::NFS3ERR_DQUOT => f.write_str("NFS3ERR_DQUOT"),
            Self::NFS3ERR_STALE => f.write_str("NFS3ERR_STALE"),
            Self::NFS3ERR_REMOTE => f.write_str("NFS3ERR_REMOTE"),
            Self::NFS3ERR_BADHANDLE => f.write_str("NFS3ERR_BADHANDLE"),
            Self::NFS3ERR_NOT_SYNC => f.write_str("NFS3ERR_NOT_SYNC"),
            Self::NFS3ERR_BAD_COOKIE => f.write_str("NFS3ERR_BAD_COOKIE"),
            Self::NFS3ERR_NOTSUPP => f.write_str("NFS3ERR_NOTSUPP"),
            Self::NFS3ERR_TOOSMALL => f.write_str("NFS3ERR_TOOSMALL"),
            Self::NFS3ERR_SERVERFAULT => f.write_str("NFS3ERR_SERVERFAULT"),
            Self::NFS3ERR_BADTYPE => f.write_str("NFS3ERR_BADTYPE"),
            Self::NFS3ERR_JUKEBOX => f.write_str("NFS3ERR_JUKEBOX"),
            Self::Unknown(v) => write!(f, "NFS3ERR_UNKNOWN({v})"),
        }
    }
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, XdrCodec)]
pub struct nfstime3 {
    pub seconds: u32,
    pub nseconds: u32,
}

impl TryFrom<std::time::SystemTime> for nfstime3 {
    type Error = std::time::SystemTimeError;

    fn try_from(time: std::time::SystemTime) -> Result<Self, Self::Error> {
        time.duration_since(std::time::UNIX_EPOCH).map(|duration| Self { seconds: u32::try_from(duration.as_secs()).unwrap_or(u32::MAX), nseconds: duration.subsec_nanos() })
    }
}

impl From<nfstime3> for std::time::SystemTime {
    fn from(nfs_time: nfstime3) -> Self {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::from(nfs_time.seconds)) + std::time::Duration::from_nanos(u64::from(nfs_time.nseconds))
    }
}

impl From<&nfstime3> for std::time::SystemTime {
    fn from(nfs_time: &nfstime3) -> Self {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::from(nfs_time.seconds)) + std::time::Duration::from_nanos(u64::from(nfs_time.nseconds))
    }
}

#[derive(Default, Debug, Clone, Copy, XdrCodec)]
pub struct sattr3 {
    pub mode: set_mode3,
    pub uid: set_uid3,
    pub gid: set_gid3,
    pub size: set_size3,
    pub atime: set_atime,
    pub mtime: set_mtime,
}

#[derive(Default, Debug, Clone, Copy, XdrCodec)]
#[non_exhaustive]
pub enum set_atime {
    #[default]
    #[xdr(0)]
    DONT_CHANGE, // = 0,
    #[xdr(1)]
    SET_TO_SERVER_TIME, // = 1,
    #[xdr(2)]
    SET_TO_CLIENT_TIME(nfstime3), // = 2,
}

#[derive(Default, Debug, Clone, Copy, XdrCodec)]
#[non_exhaustive]
pub enum set_mtime {
    #[default]
    #[xdr(0)]
    DONT_CHANGE, // = 0,
    #[xdr(1)]
    SET_TO_SERVER_TIME, // = 1,
    #[xdr(2)]
    SET_TO_CLIENT_TIME(nfstime3), // = 2,
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, XdrCodec)]
pub struct specdata3 {
    pub specdata1: u32,
    pub specdata2: u32,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, XdrCodec)]
#[non_exhaustive]
pub enum stable_how {
    #[default]
    UNSTABLE = 0,
    DATA_SYNC = 1,
    FILE_SYNC = 2,
}

impl std::fmt::Display for stable_how {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UNSTABLE => "UNSTABLE",
            Self::DATA_SYNC => "DATA_SYNC",
            Self::FILE_SYNC => "FILE_SYNC",
        })
    }
}

#[derive(Debug, XdrCodec)]
pub struct symlinkdata3<'a> {
    pub symlink_attributes: sattr3,
    pub symlink_data: nfspath3<'a>,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum time_how {
    #[default]
    DONT_CHANGE = 0,
    SET_TO_SERVER_TIME = 1,
    SET_TO_CLIENT_TIME = 2,
}

#[derive(Debug, Clone, Copy, XdrCodec)]
pub struct wcc_attr {
    pub size: size3,
    pub mtime: nfstime3,
    pub ctime: nfstime3,
}

#[derive(Debug, Default, XdrCodec)]
pub struct wcc_data {
    pub before: pre_op_attr,
    pub after: post_op_attr,
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, XdrCodec)]
pub struct writeverf3(pub [u8; NFS3_WRITEVERFSIZE]);

pub type cookie3 = u64;

pub type count3 = u32;

pub type fileid3 = u64;

pub type gid3 = u32;

pub type mode3 = u32;

pub type offset3 = u64;

pub type size3 = u64;

pub type uid3 = u32;

impl Pack for mknoddata3 {
    fn packed_size(&self) -> usize {
        4 + match self {
            Self::NF3CHR(val) | Self::NF3BLK(val) => val.packed_size(),
            Self::NF3SOCK(val) | Self::NF3FIFO(val) => val.packed_size(),
            Self::default => 0,
        }
    }

    fn pack(&self, out: &mut impl Write) -> onc_xdr::Result<usize> {
        Ok(match self {
            Self::NF3CHR(val) => ftype3::NF3CHR.pack(out)? + val.pack(out)?,
            Self::NF3BLK(val) => ftype3::NF3BLK.pack(out)? + val.pack(out)?,
            Self::NF3SOCK(val) => ftype3::NF3SOCK.pack(out)? + val.pack(out)?,
            Self::NF3FIFO(val) => ftype3::NF3FIFO.pack(out)? + val.pack(out)?,
            &Self::default => return Err(onc_xdr::Error::InvalidEnumValue(u32::MAX)),
        })
    }
}

impl Unpack for mknoddata3 {
    fn unpack(input: &mut impl Read) -> onc_xdr::Result<(Self, usize)> {
        let mut sz = 0;
        let (v, dsz): (u32, _) = Unpack::unpack(input)?;
        sz += dsz;

        let v = match v {
            4 => {
                let (val, fsz) = Unpack::unpack(input)?;
                sz += fsz;
                Self::NF3CHR(val)
            },
            3 => {
                let (val, fsz) = Unpack::unpack(input)?;
                sz += fsz;
                Self::NF3BLK(val)
            },
            6 => {
                let (val, fsz) = Unpack::unpack(input)?;
                sz += fsz;
                Self::NF3SOCK(val)
            },
            7 => {
                let (val, fsz) = Unpack::unpack(input)?;
                sz += fsz;
                Self::NF3FIFO(val)
            },
            _ => Self::default,
        };

        Ok((v, sz))
    }
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, XdrCodec)]
#[non_exhaustive]
pub enum NFS_PROGRAM {
    #[default]
    NFSPROC3_NULL = 0,
    NFSPROC3_GETATTR = 1,
    NFSPROC3_SETATTR = 2,
    NFSPROC3_LOOKUP = 3,
    NFSPROC3_ACCESS = 4,
    NFSPROC3_READLINK = 5,
    NFSPROC3_READ = 6,
    NFSPROC3_WRITE = 7,
    NFSPROC3_CREATE = 8,
    NFSPROC3_MKDIR = 9,
    NFSPROC3_SYMLINK = 10,
    NFSPROC3_MKNOD = 11,
    NFSPROC3_REMOVE = 12,
    NFSPROC3_RMDIR = 13,
    NFSPROC3_RENAME = 14,
    NFSPROC3_LINK = 15,
    NFSPROC3_READDIR = 16,
    NFSPROC3_READDIRPLUS = 17,
    NFSPROC3_FSSTAT = 18,
    NFSPROC3_FSINFO = 19,
    NFSPROC3_PATHCONF = 20,
    NFSPROC3_COMMIT = 21,
}

impl TryFrom<u32> for NFS_PROGRAM {
    type Error = onc_xdr::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NFSPROC3_NULL),
            1 => Ok(Self::NFSPROC3_GETATTR),
            2 => Ok(Self::NFSPROC3_SETATTR),
            3 => Ok(Self::NFSPROC3_LOOKUP),
            4 => Ok(Self::NFSPROC3_ACCESS),
            5 => Ok(Self::NFSPROC3_READLINK),
            6 => Ok(Self::NFSPROC3_READ),
            7 => Ok(Self::NFSPROC3_WRITE),
            8 => Ok(Self::NFSPROC3_CREATE),
            9 => Ok(Self::NFSPROC3_MKDIR),
            10 => Ok(Self::NFSPROC3_SYMLINK),
            11 => Ok(Self::NFSPROC3_MKNOD),
            12 => Ok(Self::NFSPROC3_REMOVE),
            13 => Ok(Self::NFSPROC3_RMDIR),
            14 => Ok(Self::NFSPROC3_RENAME),
            15 => Ok(Self::NFSPROC3_LINK),
            16 => Ok(Self::NFSPROC3_READDIR),
            17 => Ok(Self::NFSPROC3_READDIRPLUS),
            18 => Ok(Self::NFSPROC3_FSSTAT),
            19 => Ok(Self::NFSPROC3_FSINFO),
            20 => Ok(Self::NFSPROC3_PATHCONF),
            21 => Ok(Self::NFSPROC3_COMMIT),
            _ => Err(onc_xdr::Error::InvalidEnumValue(value)),
        }
    }
}

impl std::fmt::Display for NFS_PROGRAM {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::NFSPROC3_NULL => "NFSPROC3_NULL",
            Self::NFSPROC3_GETATTR => "NFSPROC3_GETATTR",
            Self::NFSPROC3_SETATTR => "NFSPROC3_SETATTR",
            Self::NFSPROC3_LOOKUP => "NFSPROC3_LOOKUP",
            Self::NFSPROC3_ACCESS => "NFSPROC3_ACCESS",
            Self::NFSPROC3_READLINK => "NFSPROC3_READLINK",
            Self::NFSPROC3_READ => "NFSPROC3_READ",
            Self::NFSPROC3_WRITE => "NFSPROC3_WRITE",
            Self::NFSPROC3_CREATE => "NFSPROC3_CREATE",
            Self::NFSPROC3_MKDIR => "NFSPROC3_MKDIR",
            Self::NFSPROC3_SYMLINK => "NFSPROC3_SYMLINK",
            Self::NFSPROC3_MKNOD => "NFSPROC3_MKNOD",
            Self::NFSPROC3_REMOVE => "NFSPROC3_REMOVE",
            Self::NFSPROC3_RMDIR => "NFSPROC3_RMDIR",
            Self::NFSPROC3_RENAME => "NFSPROC3_RENAME",
            Self::NFSPROC3_LINK => "NFSPROC3_LINK",
            Self::NFSPROC3_READDIR => "NFSPROC3_READDIR",
            Self::NFSPROC3_READDIRPLUS => "NFSPROC3_READDIRPLUS",
            Self::NFSPROC3_FSSTAT => "NFSPROC3_FSSTAT",
            Self::NFSPROC3_FSINFO => "NFSPROC3_FSINFO",
            Self::NFSPROC3_PATHCONF => "NFSPROC3_PATHCONF",
            Self::NFSPROC3_COMMIT => "NFSPROC3_COMMIT",
        };
        write!(f, "{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Pack a value into a fresh buffer.
    fn pack_to_vec(val: &impl Pack) -> Vec<u8> {
        let mut buf = Vec::new();
        let _n = val.pack(&mut buf).expect("pack must succeed");
        buf
    }

    /// Pack then unpack a value and return the decoded copy.
    fn round_trip<T: Pack + Unpack>(val: &T) -> T {
        let buf = pack_to_vec(val);
        let (decoded, consumed) = T::unpack(&mut Cursor::new(&buf)).expect("unpack must succeed");
        assert_eq!(consumed, buf.len(), "unpack must consume every packed byte");
        decoded
    }

    // --- nfsstat3: all 28 status codes (RFC 1813 sec 2.5) ---

    #[test]
    fn nfsstat3_all_28_values_round_trip() {
        // Every status code defined in RFC 1813 sec 2.5, with its u32 discriminant.
        let cases: &[(nfsstat3, u32)] = &[
            (nfsstat3::NFS3_OK, 0),
            (nfsstat3::NFS3ERR_PERM, 1),
            (nfsstat3::NFS3ERR_NOENT, 2),
            (nfsstat3::NFS3ERR_IO, 5),
            (nfsstat3::NFS3ERR_NXIO, 6),
            (nfsstat3::NFS3ERR_ACCES, 13),
            (nfsstat3::NFS3ERR_EXIST, 17),
            (nfsstat3::NFS3ERR_XDEV, 18),
            (nfsstat3::NFS3ERR_NODEV, 19),
            (nfsstat3::NFS3ERR_NOTDIR, 20),
            (nfsstat3::NFS3ERR_ISDIR, 21),
            (nfsstat3::NFS3ERR_INVAL, 22),
            (nfsstat3::NFS3ERR_FBIG, 27),
            (nfsstat3::NFS3ERR_NOSPC, 28),
            (nfsstat3::NFS3ERR_ROFS, 30),
            (nfsstat3::NFS3ERR_MLINK, 31),
            (nfsstat3::NFS3ERR_NAMETOOLONG, 63),
            (nfsstat3::NFS3ERR_NOTEMPTY, 66),
            (nfsstat3::NFS3ERR_DQUOT, 69),
            (nfsstat3::NFS3ERR_STALE, 70),
            (nfsstat3::NFS3ERR_REMOTE, 71),
            (nfsstat3::NFS3ERR_BADHANDLE, 10001),
            (nfsstat3::NFS3ERR_NOT_SYNC, 10002),
            (nfsstat3::NFS3ERR_BAD_COOKIE, 10003),
            (nfsstat3::NFS3ERR_NOTSUPP, 10004),
            (nfsstat3::NFS3ERR_TOOSMALL, 10005),
            (nfsstat3::NFS3ERR_SERVERFAULT, 10006),
            (nfsstat3::NFS3ERR_BADTYPE, 10007),
            (nfsstat3::NFS3ERR_JUKEBOX, 10008),
        ];
        assert_eq!(cases.len(), 29, "28 error codes + NFS3_OK = 29 total");
        for &(variant, expected_disc) in cases {
            // Pack must produce big-endian u32 of the discriminant.
            let wire = pack_to_vec(&variant);
            assert_eq!(wire, expected_disc.to_be_bytes(), "packed {variant:?} must match RFC discriminant {expected_disc}");
            // Round-trip must preserve identity.
            let decoded = round_trip(&variant);
            assert_eq!(decoded, variant, "{variant:?} must survive pack/unpack");
        }
    }

    // --- ftype3: all 7 file types (RFC 1813 sec 2.6) ---

    #[test]
    fn ftype3_all_7_values_round_trip() {
        let cases: &[(ftype3, u32)] = &[(ftype3::NF3REG, 1), (ftype3::NF3DIR, 2), (ftype3::NF3BLK, 3), (ftype3::NF3CHR, 4), (ftype3::NF3LNK, 5), (ftype3::NF3SOCK, 6), (ftype3::NF3FIFO, 7)];
        for &(variant, expected_disc) in cases {
            let wire = pack_to_vec(&variant);
            assert_eq!(wire, expected_disc.to_be_bytes(), "packed {variant:?} must match RFC discriminant {expected_disc}");
            let decoded = round_trip(&variant);
            assert_eq!(decoded, variant, "{variant:?} must survive pack/unpack");
        }
    }

    // --- nfs_fh3: variable-length handle (RFC 1813 sec 2.3.1, max 64 bytes) ---

    #[test]
    fn nfs_fh3_round_trip_typical() {
        // A typical 28-byte handle (Linux knfsd ext4).
        let data: Vec<u8> = (0..28).collect();
        let fh = nfs_fh3 { data: Opaque::owned(data.clone()) };
        let decoded = round_trip(&fh);
        assert_eq!(decoded.data.as_ref(), data.as_slice());
    }

    #[test]
    fn nfs_fh3_empty_handle() {
        // Zero-length handle is legal on the wire -- a degenerate edge case.
        let fh = nfs_fh3 { data: Opaque::owned(vec![]) };
        let decoded = round_trip(&fh);
        assert!(decoded.data.as_ref().is_empty());
    }

    #[test]
    fn nfs_fh3_max_length_handle() {
        // 64 bytes is the maximum handle size (NFS3_FHSIZE, RFC 1813 sec 2.3.1).
        let data: Vec<u8> = (0..64).collect();
        let fh = nfs_fh3 { data: Opaque::owned(data.clone()) };
        let wire = pack_to_vec(&fh);
        // Wire format: 4-byte length prefix (big-endian 64) + 64 bytes of data.
        assert_eq!(wire.len(), 4 + NFS3_FHSIZE);
        assert_eq!(&wire[..4], &64_u32.to_be_bytes());
        let decoded = round_trip(&fh);
        assert_eq!(decoded.data.as_ref(), data.as_slice());
    }

    // --- diropargs3 ---

    #[test]
    fn diropargs3_round_trip() {
        let handle_bytes: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let name_bytes: Vec<u8> = b"passwd".to_vec();
        let arg = diropargs3 { dir: nfs_fh3 { data: Opaque::owned(handle_bytes.clone()) }, name: filename3(Opaque::owned(name_bytes.clone())) };
        let wire = pack_to_vec(&arg);
        let (decoded, consumed) = diropargs3::unpack(&mut Cursor::new(&wire)).expect("unpack diropargs3");
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.dir, arg.dir);
        assert_eq!(decoded.name, arg.name);
    }

    // --- stable_how: all 3 values (RFC 1813 sec 3.3.7) ---

    #[test]
    fn stable_how_all_3_values_round_trip() {
        let cases: &[(stable_how, u32)] = &[(stable_how::UNSTABLE, 0), (stable_how::DATA_SYNC, 1), (stable_how::FILE_SYNC, 2)];
        for &(variant, expected_disc) in cases {
            let wire = pack_to_vec(&variant);
            assert_eq!(wire, expected_disc.to_be_bytes(), "stable_how::{variant:?} discriminant mismatch");
            let decoded = round_trip(&variant);
            assert_eq!(decoded, variant);
        }
    }

    // --- createmode3: all 3 values (RFC 1813 sec 3.3.8) ---

    #[test]
    fn createmode3_all_3_values_round_trip() {
        let cases: &[(createmode3, u32)] = &[(createmode3::UNCHECKED, 0), (createmode3::GUARDED, 1), (createmode3::EXCLUSIVE, 2)];
        for &(variant, expected_disc) in cases {
            let wire = pack_to_vec(&variant);
            assert_eq!(wire, expected_disc.to_be_bytes(), "createmode3::{variant:?} discriminant mismatch");
            let decoded = round_trip(&variant);
            assert_eq!(decoded, variant);
        }
    }

    // --- ACCESS3 bit values (RFC 1813 sec 3.3.4) ---

    #[test]
    fn access3_bits_are_distinct_powers_of_two() {
        // RFC 1813 sec 3.3.4: each ACCESS bit is a distinct power of 2.
        assert_eq!(ACCESS3_READ, 0x0001);
        assert_eq!(ACCESS3_LOOKUP, 0x0002);
        assert_eq!(ACCESS3_MODIFY, 0x0004);
        assert_eq!(ACCESS3_EXTEND, 0x0008);
        assert_eq!(ACCESS3_DELETE, 0x0010);
        assert_eq!(ACCESS3_EXECUTE, 0x0020);

        let all = [ACCESS3_READ, ACCESS3_LOOKUP, ACCESS3_MODIFY, ACCESS3_EXTEND, ACCESS3_DELETE, ACCESS3_EXECUTE];
        for (i, &a) in all.iter().enumerate() {
            assert_eq!(a.count_ones(), 1, "ACCESS3 bit {i} must be a single power of two");
            for (j, &b) in all.iter().enumerate() {
                if i != j {
                    assert_eq!(a & b, 0, "ACCESS3 bits {i} and {j} must not overlap");
                }
            }
        }
    }

    // --- Nfs3Option (RFC 1813's optional-data XDR pattern) ---

    #[test]
    fn nfs3option_none_packs_as_zero() {
        let none: Nfs3Option<u32> = Nfs3Option::None;
        let wire = pack_to_vec(&none);
        // None = discriminant 0, no payload.
        assert_eq!(wire, 0_u32.to_be_bytes());
    }

    #[test]
    fn nfs3option_some_packs_as_one_plus_value() {
        let some: Nfs3Option<u32> = Nfs3Option::Some(42);
        let wire = pack_to_vec(&some);
        // Some = discriminant 1, then the u32 value.
        let mut expected = Vec::new();
        expected.extend_from_slice(&1_u32.to_be_bytes());
        expected.extend_from_slice(&42_u32.to_be_bytes());
        assert_eq!(wire, expected);
    }

    #[test]
    fn nfs3option_round_trip() {
        let none: Nfs3Option<u32> = Nfs3Option::None;
        let decoded_none = round_trip(&none);
        assert!(decoded_none.is_none());

        let some: Nfs3Option<u32> = Nfs3Option::Some(0xDEAD_BEEF);
        let decoded_some = round_trip(&some);
        assert!(decoded_some.is_some());
        assert_eq!(decoded_some.unwrap(), 0xDEAD_BEEF);
    }

    // --- wcc_attr (RFC 1813 sec 3.3.2, pre_op_attr carries this) ---

    #[test]
    fn wcc_attr_round_trip() {
        let attr = wcc_attr { size: 4096, mtime: nfstime3 { seconds: 1_700_000_000, nseconds: 500_000 }, ctime: nfstime3 { seconds: 1_700_000_001, nseconds: 0 } };
        let wire = pack_to_vec(&attr);
        let (decoded, consumed) = wcc_attr::unpack(&mut Cursor::new(&wire)).expect("unpack wcc_attr");
        assert_eq!(consumed, wire.len());
        assert_eq!(decoded.size, 4096);
        assert_eq!(decoded.mtime.seconds, 1_700_000_000);
        assert_eq!(decoded.mtime.nseconds, 500_000);
        assert_eq!(decoded.ctime.seconds, 1_700_000_001);
        assert_eq!(decoded.ctime.nseconds, 0);
    }

    // --- NFS program and version constants (RFC 1813 sec 3.3) ---

    #[test]
    fn nfs_program_number() {
        assert_eq!(PROGRAM, 100_003, "NFS program number must be 100003 (RFC 1813)");
    }

    #[test]
    fn nfs_version_number() {
        assert_eq!(VERSION, 3, "NFS version must be 3 (RFC 1813)");
    }

    // --- NFS_PROGRAM procedure numbers (RFC 1813 sec 3.3) ---

    #[test]
    fn nfs_procedure_numbers() {
        // All 22 NFSv3 procedure numbers as defined in RFC 1813 sec 3.3.
        assert_eq!(NFS_PROGRAM::NFSPROC3_NULL as u32, 0);
        assert_eq!(NFS_PROGRAM::NFSPROC3_GETATTR as u32, 1);
        assert_eq!(NFS_PROGRAM::NFSPROC3_SETATTR as u32, 2);
        assert_eq!(NFS_PROGRAM::NFSPROC3_LOOKUP as u32, 3);
        assert_eq!(NFS_PROGRAM::NFSPROC3_ACCESS as u32, 4);
        assert_eq!(NFS_PROGRAM::NFSPROC3_READLINK as u32, 5);
        assert_eq!(NFS_PROGRAM::NFSPROC3_READ as u32, 6);
        assert_eq!(NFS_PROGRAM::NFSPROC3_WRITE as u32, 7);
        assert_eq!(NFS_PROGRAM::NFSPROC3_CREATE as u32, 8);
        assert_eq!(NFS_PROGRAM::NFSPROC3_MKDIR as u32, 9);
        assert_eq!(NFS_PROGRAM::NFSPROC3_SYMLINK as u32, 10);
        assert_eq!(NFS_PROGRAM::NFSPROC3_MKNOD as u32, 11);
        assert_eq!(NFS_PROGRAM::NFSPROC3_REMOVE as u32, 12);
        assert_eq!(NFS_PROGRAM::NFSPROC3_RMDIR as u32, 13);
        assert_eq!(NFS_PROGRAM::NFSPROC3_RENAME as u32, 14);
        assert_eq!(NFS_PROGRAM::NFSPROC3_LINK as u32, 15);
        assert_eq!(NFS_PROGRAM::NFSPROC3_READDIR as u32, 16);
        assert_eq!(NFS_PROGRAM::NFSPROC3_READDIRPLUS as u32, 17);
        assert_eq!(NFS_PROGRAM::NFSPROC3_FSSTAT as u32, 18);
        assert_eq!(NFS_PROGRAM::NFSPROC3_FSINFO as u32, 19);
        assert_eq!(NFS_PROGRAM::NFSPROC3_PATHCONF as u32, 20);
        assert_eq!(NFS_PROGRAM::NFSPROC3_COMMIT as u32, 21);
    }

    #[test]
    fn nfs_procedure_try_from_u32_covers_all_22() {
        // Every valid procedure number must round-trip through TryFrom<u32>.
        for n in 0..=21 {
            let proc = NFS_PROGRAM::try_from(n).unwrap_or_else(|_| panic!("procedure {n} must be valid"));
            assert_eq!(proc as u32, n, "TryFrom round-trip failed for procedure {n}");
        }
        // 22 is out of range.
        assert!(NFS_PROGRAM::try_from(22).is_err());
    }

    // =========================================================================
    // Golden vector tests -- NFSv3 (RFC 1813)
    // =========================================================================

    /// Golden vector: fattr3 for a regular file (RFC 1813 sec 2.5).
    ///
    /// NF3REG, mode 0o644, uid/gid 1000, size 4096, used 8192, fsid 1,
    /// fileid 42, timestamps at 100/200/300 seconds.
    /// 84 bytes: 5 u32 (20) + 2 u64 (16) + 2 u32 specdata (8) + 2 u64 (16)
    ///           + 3 nfstime3 (24) = 84.
    #[test]
    fn golden_fattr3_regular_file() {
        #[rustfmt::skip]
        const GOLDEN: [u8; 84] = [
            // type_ = NF3REG (1)
            0x00, 0x00, 0x00, 0x01,
            // mode = 0o644 = 420 = 0x1A4
            0x00, 0x00, 0x01, 0xA4,
            // nlink = 1
            0x00, 0x00, 0x00, 0x01,
            // uid = 1000 (0x3E8)
            0x00, 0x00, 0x03, 0xE8,
            // gid = 1000
            0x00, 0x00, 0x03, 0xE8,
            // size = 4096 (u64)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            // used = 8192 (u64)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
            // rdev.specdata1 = 0
            0x00, 0x00, 0x00, 0x00,
            // rdev.specdata2 = 0
            0x00, 0x00, 0x00, 0x00,
            // fsid = 1 (u64)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            // fileid = 42 (u64)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A,
            // atime = (100, 0)
            0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00,
            // mtime = (200, 0)
            0x00, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00, 0x00,
            // ctime = (300, 0)
            0x00, 0x00, 0x01, 0x2C, 0x00, 0x00, 0x00, 0x00,
        ];

        // Unpack from golden bytes.
        let (attr, consumed) = fattr3::unpack(&mut Cursor::new(&GOLDEN[..])).unwrap();
        assert_eq!(consumed, 84);
        assert_eq!(attr.type_, ftype3::NF3REG);
        assert_eq!(attr.mode, 0o644);
        assert_eq!(attr.nlink, 1);
        assert_eq!(attr.uid, 1000);
        assert_eq!(attr.gid, 1000);
        assert_eq!(attr.size, 4096);
        assert_eq!(attr.used, 8192);
        assert_eq!(attr.rdev, specdata3 { specdata1: 0, specdata2: 0 });
        assert_eq!(attr.fsid, 1);
        assert_eq!(attr.fileid, 42);
        assert_eq!(attr.atime, nfstime3 { seconds: 100, nseconds: 0 });
        assert_eq!(attr.mtime, nfstime3 { seconds: 200, nseconds: 0 });
        assert_eq!(attr.ctime, nfstime3 { seconds: 300, nseconds: 0 });

        // Re-pack and verify exact byte equality.
        let repacked = pack_to_vec(&attr);
        assert_eq!(repacked, GOLDEN);
    }

    /// Golden vector: GETATTR3res success (RFC 1813 sec 3.3.1).
    ///
    /// NFS3_OK (0) followed by the fattr3 golden vector from above.
    #[test]
    fn golden_getattr3res_ok() {
        // Build the golden wire: status(4) + fattr3(84) = 88 bytes.
        #[rustfmt::skip]
        const GOLDEN: [u8; 88] = [
            // nfsstat3 = NFS3_OK (0)
            0x00, 0x00, 0x00, 0x00,
            // fattr3 -- same as golden_fattr3_regular_file
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x01, 0xA4,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x03, 0xE8,
            0x00, 0x00, 0x03, 0xE8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A,
            0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x2C, 0x00, 0x00, 0x00, 0x00,
        ];

        let (res, consumed) = GETATTR3res::unpack(&mut Cursor::new(&GOLDEN[..])).unwrap();
        assert_eq!(consumed, 88);
        let ok = res.unwrap();
        assert_eq!(ok.obj_attributes.type_, ftype3::NF3REG);
        assert_eq!(ok.obj_attributes.uid, 1000);
        assert_eq!(ok.obj_attributes.fileid, 42);

        // Re-pack via Nfs3Result and verify.
        let repacked_res = GETATTR3res::Ok(ok);
        let repacked = pack_to_vec(&repacked_res);
        assert_eq!(repacked, GOLDEN);
    }

    /// Golden vector: nfsstat3 error on the wire (RFC 1813 sec 2.5).
    ///
    /// NFS3ERR_STALE = 70 is the handle oracle's positive signal -- verifies
    /// the codec maps it correctly.
    #[test]
    fn golden_nfsstat3_stale() {
        // 70 = 0x46
        const GOLDEN: [u8; 4] = [0x00, 0x00, 0x00, 0x46];

        let (status, consumed) = nfsstat3::unpack(&mut Cursor::new(&GOLDEN[..])).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(status, nfsstat3::NFS3ERR_STALE);

        let repacked = pack_to_vec(&status);
        assert_eq!(repacked, GOLDEN);
    }
}
