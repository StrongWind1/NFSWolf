//! Pure-Rust parser for Linux glibc `struct utmpx` and `struct lastlog` binary records.
//!
//! Used by the shell's `last`, `lastb`, and `lastlog` commands to decode
//! `/var/log/wtmp`, `/var/log/btmp`, and `/var/log/lastlog` after they have been
//! read out of an NFS export (typically via an `escape-root` handle).
//!
//! The on-disk layouts are fixed by the Linux/glibc ABI and are identical on
//! every common architecture (x86_64, aarch64, armhf, ppc64le) regardless of
//! native time_t width -- the time fields are explicitly 32-bit. See:
//!
//! - util-linux 2.42 `login-utils/last.c` (uses `<utmpx.h>`, reads
//!   `sizeof(struct utmpx)` per record)
//! - util-linux 2.42 `liblastlog2/src/lastlog2.c::ll2_import_lastlog()`
//!   (reads classic flat `/var/log/lastlog` via `<lastlog.h>::struct lastlog`)
//! - glibc `<bits/utmp.h>` and `<bits/utmpx.h>` (struct definition)
//! - glibc `<bits/lastlog.h>` (struct lastlog definition)
//!
//! struct utmpx is 384 bytes; struct lastlog is 292 bytes.

/// Length of the tty device name field (`ut_line` / `ll_line`).
/// Per glibc `<bits/utmp.h>`: `#define UT_LINESIZE 32`.
pub const UT_LINESIZE: usize = 32;

/// Length of the username field (`ut_user`).
/// Per glibc `<bits/utmp.h>`: `#define UT_NAMESIZE 32`.
pub const UT_NAMESIZE: usize = 32;

/// Length of the host field (`ut_host` / `ll_host`).
/// Per glibc `<bits/utmp.h>`: `#define UT_HOSTSIZE 256`.
pub const UT_HOSTSIZE: usize = 256;

/// Size of one wtmp/btmp record on disk.
/// Per glibc `struct utmpx`: 2+2+4+32+4+32+256+4+4+8+16+20 = 384 bytes.
pub const UTMP_RECORD_SIZE: usize = 384;

/// Size of one lastlog record on disk.
/// Per glibc `struct lastlog`: 4+32+256 = 292 bytes.
pub const LASTLOG_RECORD_SIZE: usize = 292;

/// `ut_type` values from glibc `<bits/utmp.h>`.
/// Per util-linux 2.42 `login-utils/last.c` lines 130-133, 786-892.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtType {
    /// Record is empty / unused.
    Empty,
    /// Change in system run-level (`init` writes these).
    RunLvl,
    /// Time of system boot.
    BootTime,
    /// Time after system clock change.
    NewTime,
    /// Time before system clock change.
    OldTime,
    /// Process spawned by `init`.
    InitProcess,
    /// Session leader process for user login.
    LoginProcess,
    /// Normal user process.
    UserProcess,
    /// Terminated process.
    DeadProcess,
    /// Accounting (rare).
    Accounting,
    /// Anything outside the documented enum (forwards-compat).
    Other(i16),
}

impl UtType {
    /// Decode the on-disk 16-bit value into a `UtType`.
    #[must_use]
    pub const fn from_raw(v: i16) -> Self {
        match v {
            0 => Self::Empty,
            1 => Self::RunLvl,
            2 => Self::BootTime,
            3 => Self::NewTime,
            4 => Self::OldTime,
            5 => Self::InitProcess,
            6 => Self::LoginProcess,
            7 => Self::UserProcess,
            8 => Self::DeadProcess,
            9 => Self::Accounting,
            n => Self::Other(n),
        }
    }
}

/// One decoded wtmp/btmp record. Field semantics match glibc `struct utmpx`.
#[derive(Debug, Clone)]
pub struct UtmpRecord {
    /// Record kind (login, logout, reboot, runlevel, ...).
    pub ut_type: UtType,
    /// PID of the login process.
    pub pid: i32,
    /// tty device name (without the `/dev/` prefix) or pseudo-tty marker (`~`).
    pub line: String,
    /// `ut_id` -- the four-byte identifier `init` uses.
    pub id: [u8; 4],
    /// Username (or sysvinit pseudo-user like `reboot`, `shutdown`, `runlevel`).
    pub user: String,
    /// Hostname or IP string (legacy clients put kernel version here for boot).
    pub host: String,
    /// `ut_exit.e_termination`.
    pub e_termination: i16,
    /// `ut_exit.e_exit`.
    pub e_exit: i16,
    /// Session ID (only populated by some windowing terminals).
    pub session: i32,
    /// `ut_tv.tv_sec` -- seconds since Unix epoch (32-bit).
    pub tv_sec: i32,
    /// `ut_tv.tv_usec` -- microseconds (32-bit).
    pub tv_usec: i32,
    /// `ut_addr_v6` -- 16 raw bytes; IPv4 stored in the first 4 bytes.
    pub addr_v6: [u8; 16],
}

impl UtmpRecord {
    /// Decode a single 384-byte record.
    ///
    /// Returns `None` if `bytes.len() != UTMP_RECORD_SIZE`. All field accesses
    /// after the length check go through `slice::get` so a corrupt record can
    /// never panic the parser.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        // Pin the slice to the canonical fixed-size layout. Everything past
        // this point operates on a `&[u8; 384]`-shaped reference via helpers.
        if bytes.len() != UTMP_RECORD_SIZE {
            return None;
        }
        // Field offsets from glibc `struct utmpx` layout. The implicit 2-byte
        // padding between ut_type and ut_pid is required by ABI alignment of
        // pid_t (a 4-byte int).
        let ut_type = i16::from_ne_bytes(read_arr::<2>(bytes, 0)?);
        let pid = i32::from_ne_bytes(read_arr::<4>(bytes, 4)?);
        let line = read_cstr_at(bytes, 8, UT_LINESIZE)?;
        let id = read_arr::<4>(bytes, 40)?;
        let user = read_cstr_at(bytes, 44, UT_NAMESIZE)?;
        let host = read_cstr_at(bytes, 76, UT_HOSTSIZE)?;
        let e_termination = i16::from_ne_bytes(read_arr::<2>(bytes, 332)?);
        let e_exit = i16::from_ne_bytes(read_arr::<2>(bytes, 334)?);
        let session = i32::from_ne_bytes(read_arr::<4>(bytes, 336)?);
        let tv_sec = i32::from_ne_bytes(read_arr::<4>(bytes, 340)?);
        let tv_usec = i32::from_ne_bytes(read_arr::<4>(bytes, 344)?);
        let addr_v6 = read_arr::<16>(bytes, 348)?;
        Some(Self { ut_type: UtType::from_raw(ut_type), pid, line, id, user, host, e_termination, e_exit, session, tv_sec, tv_usec, addr_v6 })
    }

    /// True when `ut_addr_v6` decodes as an IPv4-mapped or plain-IPv4 address.
    /// Mirrors the heuristic in util-linux `last.c::dns_lookup()` (lines 311-329).
    #[must_use]
    pub fn addr_is_ipv4(&self) -> bool {
        let a = self.addr_u32_le();
        // IPv4-in-IPv6 mapped: ::ffff:x.x.x.x -> first 8 bytes 0, then 0xffff in network order.
        let mapped = a[0] == 0 && a[1] == 0 && a[2] == u32::from_be(0x0000_ffff);
        // Plain IPv4 stored in the first 4 bytes with the rest zero.
        mapped || (a[1] == 0 && a[2] == 0 && a[3] == 0)
    }

    /// Render `ut_addr_v6` as a numeric address string. Empty string when zero.
    #[must_use]
    pub fn addr_string(&self) -> String {
        use std::fmt::Write as _;

        if self.addr_v6.iter().all(|b| *b == 0) {
            return String::new();
        }
        let a = self.addr_u32_le();
        if self.addr_is_ipv4() {
            // For an IPv4-mapped address the v4 octets live in a[3]; for plain v4 they live in a[0].
            let mapped = a[0] == 0 && a[1] == 0 && a[2] == u32::from_be(0x0000_ffff);
            let raw = if mapped { a[3] } else { a[0] };
            let octets = raw.to_le_bytes();
            return octets.iter().enumerate().fold(String::new(), |mut acc, (i, byte)| {
                if i > 0 {
                    acc.push('.');
                }
                acc.push_str(&byte.to_string());
                acc
            });
        }
        // Render as a hex IPv6 group string. Faithful but not RFC-5952-compressed.
        let mut s = String::with_capacity(39);
        for (i, pair) in self.addr_v6.chunks_exact(2).enumerate() {
            if i > 0 {
                s.push(':');
            }
            // chunks_exact(2) guarantees pair.len() == 2 -- safe to use a fold here.
            let group: u16 = pair.iter().fold(0u16, |acc, b| (acc << 8) | u16::from(*b));
            let _ = write!(s, "{group:x}");
        }
        s
    }

    fn addr_u32_le(&self) -> [u32; 4] {
        // chunks_exact(4) on a fixed [u8;16] yields exactly 4 chunks, each
        // exactly 4 bytes -- never panics, and avoids slice indexing.
        let mut out = [0u32; 4];
        for (slot, chunk) in out.iter_mut().zip(self.addr_v6.chunks_exact(4)) {
            if let Ok(arr) = <[u8; 4]>::try_from(chunk) {
                *slot = u32::from_ne_bytes(arr);
            }
        }
        out
    }
}

/// Parse a wtmp/btmp blob into records. Trailing partial records are silently dropped.
#[must_use]
pub fn parse_utmp(bytes: &[u8]) -> Vec<UtmpRecord> {
    bytes.chunks_exact(UTMP_RECORD_SIZE).filter_map(UtmpRecord::from_bytes).collect()
}

/// One decoded lastlog slot. The slot's `uid` is the array index in the file.
#[derive(Debug, Clone)]
pub struct LastlogRecord {
    /// Linux UID this slot belongs to (file offset / 292).
    pub uid: u32,
    /// Login time (Unix seconds, 32-bit on disk per glibc layout).
    pub ll_time: i32,
    /// tty device used for the most recent login.
    pub ll_line: String,
    /// Source host of the most recent login.
    pub ll_host: String,
}

/// Parse a `/var/log/lastlog` blob into one record per slot. Empty slots
/// (`ll_time == 0`) are returned too -- the caller filters as needed.
///
/// Per util-linux 2.42 `liblastlog2/src/lastlog2.c::ll2_import_lastlog()`, the
/// file is an array indexed by UID; offset = uid * sizeof(struct lastlog).
#[must_use]
pub fn parse_lastlog(bytes: &[u8]) -> Vec<LastlogRecord> {
    bytes
        .chunks_exact(LASTLOG_RECORD_SIZE)
        .enumerate()
        .filter_map(|(uid, chunk)| {
            let ll_time = i32::from_ne_bytes(read_arr::<4>(chunk, 0)?);
            let ll_line = read_cstr_at(chunk, 4, UT_LINESIZE)?;
            let ll_host = read_cstr_at(chunk, 4 + UT_LINESIZE, UT_HOSTSIZE)?;
            Some(LastlogRecord { uid: u32::try_from(uid).unwrap_or(u32::MAX), ll_time, ll_line, ll_host })
        })
        .collect()
}

/// Parse `/etc/passwd` content into `(uid, username)` pairs for lastlog rendering.
///
/// Tolerant of blank lines and comments; ignores entries that don't have at
/// least three colon-separated fields or whose UID isn't a valid `u32`.
#[must_use]
pub fn parse_passwd(bytes: &[u8]) -> Vec<(u32, String)> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(':');
        let user = parts.next().unwrap_or("").to_owned();
        let _passwd = parts.next();
        let uid_str = parts.next().unwrap_or("");
        if user.is_empty() {
            continue;
        }
        if let Ok(uid) = uid_str.parse::<u32>() {
            out.push((uid, user));
        }
    }
    out
}

/// Read a fixed-size byte array out of a slice at a given offset, bounds-checked.
fn read_arr<const N: usize>(buf: &[u8], off: usize) -> Option<[u8; N]> {
    let end = off.checked_add(N)?;
    let slice = buf.get(off..end)?;
    <[u8; N]>::try_from(slice).ok()
}

/// Decode a NUL-terminated, NUL-padded fixed-width C string from `buf[off..off+len]`.
fn read_cstr_at(buf: &[u8], off: usize, len: usize) -> Option<String> {
    let end = off.checked_add(len)?;
    let slice = buf.get(off..end)?;
    let nul = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
    let payload = slice.get(..nul)?;
    Some(String::from_utf8_lossy(payload).into_owned())
}

#[cfg(test)]
#[allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing, reason = "unit test  --  lints are suppressed per project policy")]
mod tests {
    use super::*;

    fn make_utmp(ut_type: i16, pid: i32, line: &str, user: &str, host: &str, tv_sec: i32) -> [u8; UTMP_RECORD_SIZE] {
        let mut buf = [0u8; UTMP_RECORD_SIZE];
        buf[0..2].copy_from_slice(&ut_type.to_ne_bytes());
        buf[4..8].copy_from_slice(&pid.to_ne_bytes());
        let lb = line.as_bytes();
        buf[8..8 + lb.len().min(UT_LINESIZE)].copy_from_slice(&lb[..lb.len().min(UT_LINESIZE)]);
        let ub = user.as_bytes();
        buf[44..44 + ub.len().min(UT_NAMESIZE)].copy_from_slice(&ub[..ub.len().min(UT_NAMESIZE)]);
        let hb = host.as_bytes();
        buf[76..76 + hb.len().min(UT_HOSTSIZE)].copy_from_slice(&hb[..hb.len().min(UT_HOSTSIZE)]);
        buf[340..344].copy_from_slice(&tv_sec.to_ne_bytes());
        buf
    }

    #[test]
    fn record_size_matches_glibc() {
        // The on-disk record must always be 384 bytes -- if this drifts, every
        // file reader would silently misalign every record after the first.
        assert_eq!(UTMP_RECORD_SIZE, 384);
        assert_eq!(LASTLOG_RECORD_SIZE, 292);
    }

    #[test]
    fn parses_user_process_record() {
        let raw = make_utmp(7, 1234, "pts/0", "alice", "10.0.0.5", 1_700_000_000);
        let rec = UtmpRecord::from_bytes(&raw).expect("parses");
        assert_eq!(rec.ut_type, UtType::UserProcess);
        assert_eq!(rec.pid, 1234);
        assert_eq!(rec.line, "pts/0");
        assert_eq!(rec.user, "alice");
        assert_eq!(rec.host, "10.0.0.5");
        assert_eq!(rec.tv_sec, 1_700_000_000);
    }

    #[test]
    fn parses_boot_pseudo_record() {
        // sysvinit writes BOOT_TIME with line="~" user="reboot" host=<kernel>.
        let raw = make_utmp(2, 0, "~", "reboot", "6.8.0-110-generic", 1_777_418_477);
        let rec = UtmpRecord::from_bytes(&raw).expect("parses");
        assert_eq!(rec.ut_type, UtType::BootTime);
        assert_eq!(rec.line, "~");
        assert_eq!(rec.user, "reboot");
        assert!(rec.host.starts_with("6.8."));
    }

    #[test]
    fn parse_utmp_drops_partial_trailing_record() {
        // Two full records plus 100 trailing bytes -> still two records.
        let mut buf = Vec::new();
        buf.extend_from_slice(&make_utmp(2, 0, "~", "reboot", "k1", 1));
        buf.extend_from_slice(&make_utmp(2, 0, "~", "reboot", "k2", 2));
        buf.extend(std::iter::repeat_n(0u8, 100));
        let recs = parse_utmp(&buf);
        assert_eq!(recs.len(), 2);
    }

    #[test]
    fn parses_lastlog_indexed_by_uid() {
        // Three slots: uid 0 unset, uid 1 set, uid 2 set.
        let mut buf = vec![0u8; LASTLOG_RECORD_SIZE * 3];
        buf[292..296].copy_from_slice(&1_700_000_000_i32.to_ne_bytes());
        buf[296..296 + 5].copy_from_slice(b"pts/1");
        buf[(296 + UT_LINESIZE)..(296 + UT_LINESIZE + 9)].copy_from_slice(b"10.0.0.10");
        buf[584..588].copy_from_slice(&1_700_000_500_i32.to_ne_bytes());
        buf[588..588 + 5].copy_from_slice(b"pts/2");

        let recs = parse_lastlog(&buf);
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].uid, 0);
        assert_eq!(recs[0].ll_time, 0);
        assert_eq!(recs[1].uid, 1);
        assert_eq!(recs[1].ll_time, 1_700_000_000);
        assert_eq!(recs[1].ll_line, "pts/1");
        assert_eq!(recs[1].ll_host, "10.0.0.10");
        assert_eq!(recs[2].uid, 2);
        assert_eq!(recs[2].ll_time, 1_700_000_500);
    }

    #[test]
    fn parses_passwd_skips_garbage() {
        let raw = b"# comment\n\
                    root:x:0:0:root:/root:/bin/bash\n\
                    \n\
                    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
                    bogus_no_uid::not-a-number:::::\n";
        let entries = parse_passwd(raw);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (0, "root".to_owned()));
        assert_eq!(entries[1], (1, "daemon".to_owned()));
    }

    #[test]
    fn ipv4_address_renders_dotted() {
        let mut rec = UtmpRecord::from_bytes(&make_utmp(7, 1, "pts/0", "u", "h", 1)).expect("parses");
        rec.addr_v6[0] = 10;
        rec.addr_v6[1] = 0;
        rec.addr_v6[2] = 0;
        rec.addr_v6[3] = 5;
        assert_eq!(rec.addr_string(), "10.0.0.5");
    }
}
