//! AUTH_DH (AUTH_DES) session management -- [RFC 1057] S9.3.
//!
//! The Diffie-Hellman key exchange, DES timestamp encryption, and session
//! lifecycle that drive AUTH_DH credentials.  The wire codec lives in
//! [`crate::auth`]; this module provides the cryptographic operations and
//! the state machine that builds credentials from them.
//!
//! AUTH_DH is deprecated (RFC 5531 sec. 8.2) and effectively extinct, but
//! a security tool needs to speak it when probing servers that still
//! advertise the flavor.  Feature-gated behind `auth-dh` so default builds
//! carry no DES dependency.
//!
//! [RFC 1057]: https://www.rfc-editor.org/rfc/rfc1057

use std::time::{SystemTime, UNIX_EPOCH};

use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use des::Des;
use onc_xdr::Unpack;

use crate::auth::{AuthDesCred, AuthDesVerf};
use crate::rpc::{auth_flavor, opaque_auth};

// --- DH Constants (RFC 1057 S9.3.5) ---

/// Diffie-Hellman base for AUTH_DH key exchange (RFC 1057 S9.3.5).
///
/// The RFC specifies BASE = 3.  Stored as a 192-bit big-endian byte array
/// to match the modulus representation.
pub const DH_BASE: [u8; 24] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];

/// Diffie-Hellman 192-bit modulus for AUTH_DH key exchange (RFC 1057 S9.3.5).
///
/// Hex: `d4a0ba0250b6fd2ec626e7efd637df76c716e22d0944b88b`
pub const DH_MODULUS: [u8; 24] = [0xd4, 0xa0, 0xba, 0x02, 0x50, 0xb6, 0xfd, 0x2e, 0xc6, 0x26, 0xe7, 0xef, 0xd6, 0x37, 0xdf, 0x76, 0xc7, 0x16, 0xe2, 0x2d, 0x09, 0x44, 0xb8, 0x8b];

/// AUTH_DH timestamps count from midnight March 1, 1970, not the Unix
/// epoch (Jan 1, 1970).  The offset is 59 days (RFC 1057 S9.3.4).
///
/// January (31) + February (28, 1970 is not a leap year) = 59 days.
const AUTH_DH_EPOCH_OFFSET: u64 = 59 * 24 * 3600; // 5_097_600 seconds

/// Default window (credential lifetime) in seconds (RFC 1057 S9.3.4).
const DEFAULT_WINDOW: u32 = 300;

// --- 192-bit Modular Arithmetic ---
//
// AUTH_DH uses 192-bit Diffie-Hellman, so we need modular exponentiation
// over 192-bit integers.  The numbers are small enough that schoolbook
// multiplication is efficient (no need for Karatsuba or external bignum
// crates).
//
// Internal representation: `[u64; 3]` in little-endian limb order.
//   limbs[0] = least significant 64 bits
//   limbs[1] = middle 64 bits
//   limbs[2] = most significant 64 bits
//
// Public API uses `[u8; 24]` in big-endian byte order (network order).

/// Convert a 24-byte big-endian number to 3 little-endian u64 limbs.
fn from_be_bytes(bytes: &[u8; 24]) -> [u64; 3] {
    [
        u64::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23]]),
        u64::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]]),
        u64::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]),
    ]
}

/// Convert 3 little-endian u64 limbs back to a 24-byte big-endian number.
fn to_be_bytes(limbs: &[u64; 3]) -> [u8; 24] {
    let hi = limbs[2].to_be_bytes();
    let mid = limbs[1].to_be_bytes();
    let lo = limbs[0].to_be_bytes();
    [hi[0], hi[1], hi[2], hi[3], hi[4], hi[5], hi[6], hi[7], mid[0], mid[1], mid[2], mid[3], mid[4], mid[5], mid[6], mid[7], lo[0], lo[1], lo[2], lo[3], lo[4], lo[5], lo[6], lo[7]]
}

/// Schoolbook multiplication of two 192-bit numbers, producing a 384-bit result.
///
/// Uses u128 accumulation to handle carries cleanly.
#[expect(clippy::indexing_slicing, reason = "loop indices bounded: i,j in 0..3, so i+j <= 4 and i+3 <= 5, all within [u64; 6]")]
#[expect(clippy::cast_possible_truncation, reason = "intentional: extracting 64-bit halves from 128-bit accumulator")]
fn mul_wide(a: &[u64; 3], b: &[u64; 3]) -> [u64; 6] {
    let mut result = [0u64; 6];
    for i in 0..3 {
        let mut carry: u64 = 0;
        for j in 0..3 {
            // Each step: accumulate a[i]*b[j] + existing result + carry.
            // Maximum value: (2^64-1)^2 + (2^64-1) + (2^64-1) < 2^128, fits in u128.
            let product = u128::from(a[i]) * u128::from(b[j]) + u128::from(result[i + j]) + u128::from(carry);
            result[i + j] = product as u64;
            carry = (product >> 64) as u64;
        }
        result[i + 3] = carry;
    }
    result
}

/// Compare a 4-limb (256-bit) number against a 3-limb (192-bit) number.
///
/// Returns true if `a >= b` (with `b` zero-extended to 4 limbs).
fn ge_4_3(a: &[u64; 4], b: &[u64; 3]) -> bool {
    if a[3] > 0 {
        return true;
    }
    if a[2] != b[2] {
        return a[2] > b[2];
    }
    if a[1] != b[1] {
        return a[1] > b[1];
    }
    a[0] >= b[0]
}

/// Subtract a 3-limb number from a 4-limb number in place.
///
/// Caller must ensure `a >= b` (checked via [`ge_4_3`]).
#[expect(clippy::indexing_slicing, reason = "loop i in 0..3, all within [u64; 4] and [u64; 3]")]
fn sub_inplace(a: &mut [u64; 4], b: &[u64; 3]) {
    let mut borrow: bool = false;
    for i in 0..3 {
        let (diff, b1) = a[i].overflowing_sub(b[i]);
        let (diff, b2) = diff.overflowing_sub(u64::from(borrow));
        a[i] = diff;
        // At most one of b1/b2 can be true (see proof in module comment),
        // but OR covers both safely.
        borrow = b1 || b2;
    }
    if borrow {
        a[3] = a[3].wrapping_sub(1);
    }
}

/// Compute the remainder of a 384-bit number divided by a 192-bit modulus.
///
/// Uses binary long division: iterate from MSB to LSB of the dividend,
/// shifting each bit into the remainder and subtracting the divisor when
/// the remainder is large enough.  384 iterations for 192-bit numbers is
/// fast enough (< 1us on modern hardware).
#[expect(clippy::indexing_slicing, reason = "limb_idx = i/64 where i in 0..384, so limb_idx in 0..6, all within [u64; 6]")]
fn rem_384_by_192(dividend: &[u64; 6], divisor: &[u64; 3]) -> [u64; 3] {
    // Remainder accumulator (needs 193 bits max: 192-bit divisor + 1 bit
    // from the shift). Using 4 limbs (256 bits) for comfortable headroom.
    let mut r = [0u64; 4];

    // Process each bit from MSB (bit 383) down to LSB (bit 0).
    for i in (0..384).rev() {
        // Left-shift r by 1 bit.
        r[3] = (r[3] << 1) | (r[2] >> 63);
        r[2] = (r[2] << 1) | (r[1] >> 63);
        r[1] = (r[1] << 1) | (r[0] >> 63);
        r[0] <<= 1;

        // Bring in bit `i` of the dividend.
        let limb_idx = i / 64;
        let bit_idx = i % 64;
        r[0] |= (dividend[limb_idx] >> bit_idx) & 1;

        // If r >= divisor, subtract.
        if ge_4_3(&r, divisor) {
            sub_inplace(&mut r, divisor);
        }
    }

    [r[0], r[1], r[2]]
}

/// Modular multiplication: `(a * b) mod m`.
fn mul_mod(a: &[u64; 3], b: &[u64; 3], m: &[u64; 3]) -> [u64; 3] {
    let product = mul_wide(a, b);
    rem_384_by_192(&product, m)
}

/// Modular exponentiation: `base^exp mod modulus` (RFC 1057 S9.3.5).
///
/// Uses the standard square-and-multiply algorithm, iterating through
/// exponent bits from LSB to MSB.
///
/// All inputs and output are 192-bit big-endian byte arrays.
#[must_use]
pub fn mod_pow(base: &[u8; 24], exponent: &[u8; 24], modulus: &[u8; 24]) -> [u8; 24] {
    let m = from_be_bytes(modulus);
    let mut b = from_be_bytes(base);
    let e = from_be_bytes(exponent);

    // Reduce base mod modulus in case base >= modulus.
    let base_wide = [b[0], b[1], b[2], 0, 0, 0];
    b = rem_384_by_192(&base_wide, &m);

    let mut result: [u64; 3] = [1, 0, 0];

    for &limb in &e {
        for bit in 0..64 {
            if (limb >> bit) & 1 == 1 {
                result = mul_mod(&result, &b, &m);
            }
            // Square the base for the next bit position.
            b = mul_mod(&b, &b, &m);
        }
    }

    to_be_bytes(&result)
}

// --- DES Operations ---

/// DES-ECB encrypt a single 8-byte block.
#[must_use]
#[expect(clippy::trivially_copy_pass_by_ref, reason = "reference API matches the RustCrypto convention for key/block parameters")]
pub fn des_ecb_encrypt(key: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    let cipher = Des::new(key.into());
    let mut buf = (*block).into();
    cipher.encrypt_block(&mut buf);
    buf.into()
}

/// DES-ECB decrypt a single 8-byte block.
#[must_use]
#[expect(clippy::trivially_copy_pass_by_ref, reason = "reference API matches the RustCrypto convention for key/block parameters")]
pub fn des_ecb_decrypt(key: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    let cipher = Des::new(key.into());
    let mut buf = (*block).into();
    cipher.decrypt_block(&mut buf);
    buf.into()
}

/// DES-CBC encrypt arbitrary data (must be a multiple of 8 bytes).
///
/// Manual CBC: XOR each plaintext block with the previous ciphertext
/// block (or IV for the first block), then ECB-encrypt.
///
/// # Panics
///
/// Panics if `data.len()` is not a multiple of 8.
#[must_use]
#[expect(clippy::trivially_copy_pass_by_ref, reason = "reference API matches the RustCrypto convention for key/iv parameters")]
pub fn des_cbc_encrypt(key: &[u8; 8], iv: &[u8; 8], data: &[u8]) -> Vec<u8> {
    assert!(data.len().is_multiple_of(8), "DES-CBC data must be a multiple of 8 bytes, got {}", data.len());

    let cipher = Des::new(key.into());
    let mut result = Vec::with_capacity(data.len());
    let mut prev = *iv;

    for chunk in data.chunks_exact(8) {
        // XOR plaintext with previous ciphertext (or IV).
        let mut block = [0u8; 8];
        for (b, (c, p)) in block.iter_mut().zip(chunk.iter().zip(prev.iter())) {
            *b = c ^ p;
        }

        // ECB encrypt the XOR'd block.
        let mut buf = block.into();
        cipher.encrypt_block(&mut buf);
        let encrypted: [u8; 8] = buf.into();

        result.extend_from_slice(&encrypted);
        prev = encrypted;
    }

    result
}

/// DES-CBC decrypt arbitrary data (must be a multiple of 8 bytes).
///
/// # Panics
///
/// Panics if `data.len()` is not a multiple of 8.
#[must_use]
#[expect(clippy::trivially_copy_pass_by_ref, reason = "reference API matches the RustCrypto convention for key/iv parameters")]
pub fn des_cbc_decrypt(key: &[u8; 8], iv: &[u8; 8], data: &[u8]) -> Vec<u8> {
    assert!(data.len().is_multiple_of(8), "DES-CBC data must be a multiple of 8 bytes, got {}", data.len());

    let cipher = Des::new(key.into());
    let mut result = Vec::with_capacity(data.len());
    let mut prev = *iv;

    for chunk in data.chunks_exact(8) {
        // ECB decrypt the block.
        let mut ciphertext = [0u8; 8];
        ciphertext.copy_from_slice(chunk);
        let mut buf = ciphertext.into();
        cipher.decrypt_block(&mut buf);
        let decrypted: [u8; 8] = buf.into();

        // XOR with previous ciphertext (or IV) to get plaintext.
        let mut block = [0u8; 8];
        for (b, (d, p)) in block.iter_mut().zip(decrypted.iter().zip(prev.iter())) {
            *b = d ^ p;
        }

        result.extend_from_slice(&block);
        prev = ciphertext;
    }

    result
}

// --- DES Parity ---

/// Insert DES parity bits into an 8-byte key.
///
/// Each byte of a DES key carries 7 data bits (bits 7-1) and 1 parity
/// bit (bit 0, the LSB).  The parity bit is set so each byte has odd
/// parity (odd total number of 1-bits).
pub fn add_des_parity(key: &mut [u8; 8]) {
    for byte in key.iter_mut() {
        // Count 1-bits in the upper 7 data bits.
        let data_ones = (*byte >> 1).count_ones();
        // Set LSB to make the total count odd.
        *byte = (*byte & 0xFE) | u8::from(data_ones % 2 == 0);
    }
}

// --- DH Key Exchange ---

/// Compute a Diffie-Hellman public key: `BASE^secret mod MODULUS`.
///
/// Returns the 192-bit public key as a big-endian byte array.  The caller
/// publishes this key (e.g., via a public key directory) so the peer can
/// derive the shared common key.
#[must_use]
pub fn compute_public_key(secret: &[u8; 24]) -> [u8; 24] {
    mod_pow(&DH_BASE, secret, &DH_MODULUS)
}

/// Derive the DES common key from a DH key exchange (RFC 1057 S9.3.5).
///
/// Computes `server_pubkey^our_secret mod MODULUS`, extracts the middle
/// 8 bytes (bytes 8..16 of the 24-byte result), and inserts DES parity
/// bits.  The resulting 56-bit key (with 8 parity bits) is used to
/// encrypt the conversation key in the first AUTH_DH credential.
#[must_use]
pub fn dh_common_key(server_pubkey: &[u8; 24], our_secret: &[u8; 24]) -> [u8; 8] {
    let common = mod_pow(server_pubkey, our_secret, &DH_MODULUS);
    let mut des_key = [0u8; 8];
    des_key.copy_from_slice(&common[8..16]);
    add_des_parity(&mut des_key);
    des_key
}

// --- Timestamps ---

/// Current time in the AUTH_DH epoch (seconds since midnight March 1, 1970).
///
/// Returns `(seconds, microseconds)`.  The DH epoch is 59 days after the
/// Unix epoch, so we subtract 5,097,600 seconds from the Unix timestamp.
///
/// # Panics
///
/// Panics if the system clock is before the Unix epoch (should not happen
/// on any supported platform).
#[expect(clippy::cast_possible_truncation, reason = "DH timestamps are u32; current time fits until year 2106")]
#[expect(clippy::expect_used, reason = "system clock before Unix epoch is unrecoverable on any supported platform")]
#[must_use]
pub fn current_dh_timestamp() -> (u32, u32) {
    let unix = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock is before the Unix epoch");
    let secs = unix.as_secs().wrapping_sub(AUTH_DH_EPOCH_OFFSET);
    let usecs = unix.subsec_micros();
    (secs as u32, usecs)
}

// --- AUTH_DH Session ---

/// An AUTH_DH session tracking the DH key exchange and timestamp state.
///
/// Manages the conversation key, common key, nickname, and timestamp
/// monotonicity required by the AUTH_DH protocol (RFC 1057 S9.3).
///
/// # Usage
///
/// ```ignore
/// // Compute our public key and send it to the peer.
/// let our_secret = [/* 24 random bytes */];
/// let our_pubkey = compute_public_key(&our_secret);
///
/// // Create session after receiving the server's public key.
/// let mut session = AuthDhSession::new("unix.1000@domain", &server_pubkey, &our_secret);
///
/// // First RPC call: fullname credential.
/// let (cred, verf) = session.first_credential();
/// // ... send RPC, receive reply ...
/// session.process_reply_verf(&reply_verf);
///
/// // Subsequent calls: nickname credential.
/// let (cred, verf) = session.next_credential();
/// ```
#[derive(Debug, Clone)]
pub struct AuthDhSession {
    /// Client's network name (e.g., "unix.1000@domain").
    netname: String,
    /// Random session key encrypted and sent to the server.
    conversation_key: [u8; 8],
    /// DES key derived from the DH exchange, used to encrypt the
    /// conversation key in the first credential.
    common_key: [u8; 8],
    /// Maximum clock skew the server should tolerate (seconds).
    window: u32,
    /// Server-assigned nickname for subsequent calls, received in the
    /// server's reply verifier.
    server_nickname: Option<u32>,
    /// Last timestamp sent, for monotonicity enforcement.
    last_timestamp_secs: u32,
    /// Microsecond component of the last timestamp.
    last_timestamp_usecs: u32,
}

impl AuthDhSession {
    /// Create a new AUTH_DH session from a DH key exchange.
    ///
    /// Computes the common key from `server_pubkey^our_secret mod MODULUS`,
    /// generates a random conversation key, and sets the default window
    /// to 300 seconds.
    #[must_use]
    pub fn new(netname: &str, server_pubkey: &[u8; 24], our_secret: &[u8; 24]) -> Self {
        let common_key = dh_common_key(server_pubkey, our_secret);
        let conversation_key = random_conversation_key();

        Self { netname: netname.to_owned(), conversation_key, common_key, window: DEFAULT_WINDOW, server_nickname: None, last_timestamp_secs: 0, last_timestamp_usecs: 0 }
    }

    /// Override the default window (credential lifetime in seconds).
    pub fn set_window(&mut self, window: u32) {
        self.window = window;
    }

    /// Build a fullname credential + client verifier for the first RPC call.
    ///
    /// The credential carries the network name, the conversation key
    /// encrypted with the common DH key, and the encrypted window.  The
    /// verifier carries the encrypted timestamp and window verifier.
    ///
    /// The timestamp, window, and window-1 are packed into a 16-byte
    /// structure and CBC-encrypted with the conversation key using a zero
    /// IV (RFC 1057 S9.3.4).
    #[must_use]
    #[expect(clippy::indexing_slicing, reason = "encrypted is always 16 bytes (2 DES blocks from 16 bytes input); all slice ranges are in bounds")]
    pub fn first_credential(&mut self) -> (opaque_auth<'static>, opaque_auth<'static>) {
        let (secs, usecs) = self.next_timestamp();

        // Pack plaintext: [timestamp_secs(4) | timestamp_usecs(4) | window(4) | window-1(4)]
        let mut plaintext = [0u8; 16];
        plaintext[0..4].copy_from_slice(&secs.to_be_bytes());
        plaintext[4..8].copy_from_slice(&usecs.to_be_bytes());
        plaintext[8..12].copy_from_slice(&self.window.to_be_bytes());
        plaintext[12..16].copy_from_slice(&(self.window.wrapping_sub(1)).to_be_bytes());

        // CBC-encrypt with conversation key, IV = 0 (RFC 1057 S9.3.4).
        let iv = [0u8; 8];
        let encrypted = des_cbc_encrypt(&self.conversation_key, &iv, &plaintext);

        // ECB-encrypt the conversation key with the common DH key.
        let encrypted_conv_key = des_ecb_encrypt(&self.common_key, &self.conversation_key);

        // Split the CBC output into credential and verifier fields.
        let mut enc_timestamp = [0u8; 8];
        enc_timestamp.copy_from_slice(&encrypted[0..8]);

        let enc_window = u32::from_be_bytes([encrypted[8], encrypted[9], encrypted[10], encrypted[11]]);

        let mut enc_winverf = [0u8; 4];
        enc_winverf.copy_from_slice(&encrypted[12..16]);

        let cred = AuthDesCred::Fullname { name: self.netname.clone(), encrypted_key: encrypted_conv_key, window: enc_window };

        let verf = AuthDesVerf::Client { encrypted_timestamp: enc_timestamp, encrypted_window_verifier: enc_winverf };

        (cred.to_opaque_auth(), verf.to_opaque_auth())
    }

    /// Build a nickname credential + client verifier for subsequent RPC calls.
    ///
    /// Uses the server-assigned nickname if available; falls back to a
    /// fullname credential if `process_reply_verf` has not yet been called.
    ///
    /// The timestamp is ECB-encrypted with the conversation key
    /// (RFC 1057 S9.3.4: "All other encryptions of timestamps use ECB
    /// mode encryption").
    #[must_use]
    pub fn next_credential(&mut self) -> (opaque_auth<'static>, opaque_auth<'static>) {
        // Fall back to fullname if we don't have a nickname yet.
        let Some(nickname) = self.server_nickname else {
            return self.first_credential();
        };

        let (secs, usecs) = self.next_timestamp();

        // Pack timestamp as [secs(4) | usecs(4)] and ECB-encrypt.
        let mut ts_block = [0u8; 8];
        ts_block[0..4].copy_from_slice(&secs.to_be_bytes());
        ts_block[4..8].copy_from_slice(&usecs.to_be_bytes());
        let encrypted_ts = des_ecb_encrypt(&self.conversation_key, &ts_block);

        let cred = AuthDesCred::Nickname { nickname };
        let verf = AuthDesVerf::Client { encrypted_timestamp: encrypted_ts, encrypted_window_verifier: [0; 4] };

        (cred.to_opaque_auth(), verf.to_opaque_auth())
    }

    /// Validate the server's reply verifier and extract the nickname.
    ///
    /// The server returns the client's timestamp minus one second,
    /// ECB-encrypted with the conversation key, plus an unencrypted
    /// nickname (RFC 1057 S9.3.4).
    ///
    /// Returns `true` if the verifier is valid (correct timestamp-1 and
    /// the nickname is stored for future calls).  Returns `false` on any
    /// decoding or verification failure.
    pub fn process_reply_verf(&mut self, verf: &opaque_auth<'_>) -> bool {
        // The server's reply verifier must have AUTH_DES flavor.
        if verf.flavor != auth_flavor::AUTH_DES {
            return false;
        }

        // Unpack the verifier body.  The wire codec always decodes as
        // Client variant; as_server() reinterprets the fields.
        let body = verf.body.as_ref();
        let Ok((decoded, _)) = AuthDesVerf::unpack(&mut &body[..]) else {
            return false;
        };
        let server_verf = decoded.as_server();

        let (encrypted_ts, nickname) = match server_verf {
            AuthDesVerf::Server { encrypted_timestamp_minus_one, nickname } => (encrypted_timestamp_minus_one, nickname),
            AuthDesVerf::Client { .. } => return false,
        };

        // ECB-decrypt the server's timestamp verifier.
        let decrypted = des_ecb_decrypt(&self.conversation_key, &encrypted_ts);

        // Parse as [secs(4) | usecs(4)].
        let verf_seconds = u32::from_be_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]);
        let verf_microseconds = u32::from_be_bytes([decrypted[4], decrypted[5], decrypted[6], decrypted[7]]);

        // Verify: server returns (our_timestamp_secs - 1, our_timestamp_usecs).
        if verf_seconds != self.last_timestamp_secs.wrapping_sub(1) || verf_microseconds != self.last_timestamp_usecs {
            return false;
        }

        // Store the nickname for subsequent calls.
        self.server_nickname = Some(nickname);
        true
    }

    /// Generate a monotonically increasing timestamp.
    ///
    /// If the current wall clock would produce a timestamp <= the last one
    /// sent, bumps the microsecond counter to maintain strict ordering
    /// (RFC 1057 S9.3.2: "the server just checks ... the timestamp is
    /// greater than the one previously seen").
    fn next_timestamp(&mut self) -> (u32, u32) {
        let (mut secs, mut usecs) = current_dh_timestamp();

        // Ensure strict monotonicity.
        if secs < self.last_timestamp_secs || (secs == self.last_timestamp_secs && usecs <= self.last_timestamp_usecs) {
            secs = self.last_timestamp_secs;
            usecs = self.last_timestamp_usecs.wrapping_add(1);
            if usecs >= 1_000_000 {
                secs = secs.wrapping_add(1);
                usecs = 0;
            }
        }

        self.last_timestamp_secs = secs;
        self.last_timestamp_usecs = usecs;
        (secs, usecs)
    }

    /// Return the conversation key (for testing or diagnostics).
    #[must_use]
    pub fn conversation_key(&self) -> &[u8; 8] {
        &self.conversation_key
    }

    /// Return the common DH key (for testing or diagnostics).
    #[must_use]
    pub fn common_key(&self) -> &[u8; 8] {
        &self.common_key
    }
}

/// Generate a random DES conversation key with correct parity.
fn random_conversation_key() -> [u8; 8] {
    let mut key = [0u8; 8];
    for byte in &mut key {
        *byte = fastrand::u8(..);
    }
    add_des_parity(&mut key);
    key
}

// --- Tests ---

#[cfg(test)]
mod tests {
    #![expect(clippy::pedantic, reason = "unit test -- lints are suppressed per project policy")]

    use super::*;

    // --- 192-bit arithmetic ---

    #[test]
    fn mod_pow_base_to_zero_is_one() {
        let zero = [0u8; 24];
        let result = mod_pow(&DH_BASE, &zero, &DH_MODULUS);
        let mut expected = [0u8; 24];
        expected[23] = 1;
        assert_eq!(result, expected, "BASE^0 mod MODULUS should be 1");
    }

    #[test]
    fn mod_pow_base_to_one_is_base() {
        let mut one = [0u8; 24];
        one[23] = 1;
        let result = mod_pow(&DH_BASE, &one, &DH_MODULUS);
        assert_eq!(result, DH_BASE, "BASE^1 mod MODULUS should be BASE");
    }

    #[test]
    fn mod_pow_base_to_two_is_nine() {
        let mut two = [0u8; 24];
        two[23] = 2;
        let result = mod_pow(&DH_BASE, &two, &DH_MODULUS);
        let mut expected = [0u8; 24];
        expected[23] = 9; // 3^2 = 9
        assert_eq!(result, expected, "BASE^2 mod MODULUS should be 9");
    }

    #[test]
    fn mod_pow_base_to_ten() {
        let mut ten = [0u8; 24];
        ten[23] = 10;
        let result = mod_pow(&DH_BASE, &ten, &DH_MODULUS);
        // 3^10 = 59049 = 0xE6A9
        let mut expected = [0u8; 24];
        expected[22] = 0xE6;
        expected[23] = 0xA9;
        assert_eq!(result, expected, "BASE^10 mod MODULUS should be 59049");
    }

    #[test]
    fn mod_pow_with_modular_reduction() {
        // 3^200 mod MODULUS exercises modular reduction since 3^200 >> 2^192.
        let mut exp = [0u8; 24];
        exp[23] = 200;
        let result = mod_pow(&DH_BASE, &exp, &DH_MODULUS);
        // Verify result < modulus.
        assert!(result < DH_MODULUS, "result should be less than modulus");
        // Verify result != 0 (3 is coprime to the modulus).
        assert_ne!(result, [0u8; 24], "result should not be zero");
    }

    #[test]
    fn dh_key_exchange_commutativity() {
        // Core DH property: pubB^secA mod M == pubA^secB mod M.
        let mut secret_alice = [0u8; 24];
        secret_alice[23] = 42;
        secret_alice[22] = 1;

        let mut secret_bob = [0u8; 24];
        secret_bob[23] = 137;
        secret_bob[22] = 2;

        let pub_alice = compute_public_key(&secret_alice);
        let pub_bob = compute_public_key(&secret_bob);

        let common_from_alice = mod_pow(&pub_bob, &secret_alice, &DH_MODULUS);
        let common_from_bob = mod_pow(&pub_alice, &secret_bob, &DH_MODULUS);

        assert_eq!(common_from_alice, common_from_bob, "DH key exchange must be commutative");
    }

    #[test]
    fn dh_common_key_derives_same_key_for_both_parties() {
        let mut secret_alice = [0u8; 24];
        secret_alice[23] = 99;
        secret_alice[20] = 7;

        let mut secret_bob = [0u8; 24];
        secret_bob[23] = 200;
        secret_bob[19] = 3;

        let pub_alice = compute_public_key(&secret_alice);
        let pub_bob = compute_public_key(&secret_bob);

        let key_for_alice = dh_common_key(&pub_bob, &secret_alice);
        let key_for_bob = dh_common_key(&pub_alice, &secret_bob);

        assert_eq!(key_for_alice, key_for_bob, "both parties must derive the same DES common key");
    }

    // --- DES operations ---

    #[test]
    fn des_ecb_encrypt_decrypt_round_trip() {
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let plaintext = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48];

        let ciphertext = des_ecb_encrypt(&key, &plaintext);
        assert_ne!(ciphertext, plaintext, "ciphertext should differ from plaintext");

        let decrypted = des_ecb_decrypt(&key, &ciphertext);
        assert_eq!(decrypted, plaintext, "decryption should recover the original");
    }

    #[test]
    fn des_ecb_different_keys_produce_different_ciphertext() {
        let key_primary = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let key_alternate = [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        let plaintext = [0x41; 8];

        let ct_primary = des_ecb_encrypt(&key_primary, &plaintext);
        let ct_alternate = des_ecb_encrypt(&key_alternate, &plaintext);
        assert_ne!(ct_primary, ct_alternate, "different keys must produce different ciphertext");
    }

    #[test]
    fn des_cbc_encrypt_two_blocks() {
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let iv = [0u8; 8];
        let data = [0x41u8; 16]; // two blocks

        let encrypted = des_cbc_encrypt(&key, &iv, &data);
        assert_eq!(encrypted.len(), 16, "output must be same length as input");

        // First block should match ECB(key, data[0..8] XOR iv).
        // Since iv = 0, first block = ECB(key, data[0..8]).
        let first_ecb = des_ecb_encrypt(&key, &[0x41; 8]);
        assert_eq!(&encrypted[0..8], &first_ecb, "first CBC block with zero IV = ECB");

        // Second block should differ from first (CBC chaining).
        assert_ne!(&encrypted[0..8], &encrypted[8..16], "CBC chaining should produce different blocks");

        // Round-trip.
        let decrypted = des_cbc_decrypt(&key, &iv, &encrypted);
        assert_eq!(&decrypted, &data, "CBC decrypt should recover original");
    }

    #[test]
    #[should_panic(expected = "DES-CBC data must be a multiple of 8 bytes")]
    fn des_cbc_encrypt_rejects_unaligned_data() {
        let key = [0u8; 8];
        let iv = [0u8; 8];
        let _result = des_cbc_encrypt(&key, &iv, &[0u8; 7]);
    }

    // --- DES parity ---

    #[test]
    fn add_des_parity_produces_odd_parity() {
        let mut key = [0b1010_1010, 0b0000_0000, 0b1111_1110, 0b0101_0100, 0xFF, 0x00, 0x01, 0xFE];
        add_des_parity(&mut key);

        for (i, &byte) in key.iter().enumerate() {
            let ones = byte.count_ones();
            assert_eq!(ones % 2, 1, "byte {i} (0x{byte:02X}) should have odd parity, has {ones} ones");
        }
    }

    #[test]
    fn add_des_parity_preserves_data_bits() {
        let original = [0b1010_1010, 0b1100_1100, 0b1111_0000, 0b0000_1111, 0b1001_0110, 0b0110_1001, 0b1111_1111, 0b0000_0000];
        let mut key = original;
        add_des_parity(&mut key);

        for i in 0..8 {
            // Data bits are bits 7..1 (upper 7 bits).
            assert_eq!(key[i] & 0xFE, original[i] & 0xFE, "byte {i}: data bits should be preserved");
        }
    }

    #[test]
    fn add_des_parity_all_zeros() {
        let mut key = [0u8; 8];
        add_des_parity(&mut key);
        // 0 data bits (all zero) -> even count of ones -> parity bit = 1.
        for &byte in &key {
            assert_eq!(byte, 0x01, "zero data should get parity bit 1");
        }
    }

    // --- Timestamps ---

    #[test]
    fn current_dh_timestamp_is_reasonable() {
        let (secs, usecs) = current_dh_timestamp();
        // In 2024-2030, the DH timestamp should be around 1.7-1.9 billion.
        assert!(secs > 1_700_000_000, "timestamp seconds ({secs}) too small for current era");
        assert!(usecs < 1_000_000, "microseconds ({usecs}) must be < 1,000,000");
    }

    #[test]
    fn auth_dh_epoch_offset_is_59_days() {
        assert_eq!(AUTH_DH_EPOCH_OFFSET, 5_097_600, "59 days * 86400 seconds/day");
    }

    // --- Full session ---

    #[test]
    fn first_credential_produces_auth_des_flavor() {
        let mut sec_client = [0u8; 24];
        sec_client[23] = 17;
        let mut sec_server = [0u8; 24];
        sec_server[23] = 31;

        let server_pub = compute_public_key(&sec_server);
        let mut session = AuthDhSession::new("unix.1000@test", &server_pub, &sec_client);

        let (cred, verf) = session.first_credential();
        assert_eq!(cred.flavor, auth_flavor::AUTH_DES, "credential must have AUTH_DES flavor");
        assert_eq!(verf.flavor, auth_flavor::AUTH_DES, "verifier must have AUTH_DES flavor");
        assert!(!cred.body.as_ref().is_empty(), "credential body must not be empty");
        assert!(!verf.body.as_ref().is_empty(), "verifier body must not be empty");
    }

    #[test]
    fn first_credential_cred_decodes_as_fullname() {
        let mut sec_client = [0u8; 24];
        sec_client[23] = 5;
        let mut sec_server = [0u8; 24];
        sec_server[23] = 7;

        let server_pub = compute_public_key(&sec_server);
        let mut session = AuthDhSession::new("unix.500@domain", &server_pub, &sec_client);

        let (cred, _verf) = session.first_credential();

        // Decode the credential body.
        let body = cred.body.as_ref();
        let (decoded, _) = AuthDesCred::unpack(&mut &body[..]).expect("credential should unpack");
        match decoded {
            AuthDesCred::Fullname { name, encrypted_key, .. } => {
                assert_eq!(name, "unix.500@domain");
                assert_ne!(encrypted_key, [0; 8], "encrypted key should not be all zeros");
            },
            AuthDesCred::Nickname { .. } => panic!("first credential should be fullname, not nickname"),
        }
    }

    #[test]
    fn first_credential_timestamp_is_encrypted_correctly() {
        // Verify we can decrypt the credential and verifier fields
        // back to a consistent plaintext.
        let mut sec_client = [0u8; 24];
        sec_client[23] = 11;
        let mut sec_server = [0u8; 24];
        sec_server[23] = 13;

        let server_pub = compute_public_key(&sec_server);
        let mut session = AuthDhSession::new("unix.0@test", &server_pub, &sec_client);
        let conv_key = *session.conversation_key();

        let (cred, verf) = session.first_credential();

        // Decode credential.
        let cred_body = cred.body.as_ref();
        let (cred_decoded, _) = AuthDesCred::unpack(&mut &cred_body[..]).expect("unpack cred");
        let enc_window_bytes = match &cred_decoded {
            AuthDesCred::Fullname { window, .. } => window.to_be_bytes(),
            _ => panic!("expected fullname"),
        };

        // Decode verifier.
        let verf_body = verf.body.as_ref();
        let (verf_decoded, _) = AuthDesVerf::unpack(&mut &verf_body[..]).expect("unpack verf");
        let (enc_ts, enc_winverf) = match verf_decoded {
            AuthDesVerf::Client { encrypted_timestamp, encrypted_window_verifier } => (encrypted_timestamp, encrypted_window_verifier),
            _ => panic!("expected client verifier"),
        };

        // Reconstruct the 16-byte ciphertext and CBC-decrypt.
        let mut ciphertext = Vec::with_capacity(16);
        ciphertext.extend_from_slice(&enc_ts);
        ciphertext.extend_from_slice(&enc_window_bytes);
        ciphertext.extend_from_slice(&enc_winverf);

        let iv = [0u8; 8];
        let plaintext = des_cbc_decrypt(&conv_key, &iv, &ciphertext);

        // Parse the plaintext.
        let ts_secs = u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
        let ts_usecs = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
        let window = u32::from_be_bytes([plaintext[8], plaintext[9], plaintext[10], plaintext[11]]);
        let winverf = u32::from_be_bytes([plaintext[12], plaintext[13], plaintext[14], plaintext[15]]);

        assert!(ts_secs > 0, "decrypted timestamp seconds should be non-zero");
        assert!(ts_usecs < 1_000_000, "decrypted microseconds should be < 1M");
        assert_eq!(window, 300, "decrypted window should match default");
        assert_eq!(winverf, 299, "decrypted window verifier should be window - 1");
    }

    #[test]
    fn next_credential_without_nickname_falls_back_to_fullname() {
        let mut sec_client = [0u8; 24];
        sec_client[23] = 3;
        let mut sec_server = [0u8; 24];
        sec_server[23] = 5;

        let server_pub = compute_public_key(&sec_server);
        let mut session = AuthDhSession::new("unix.0@test", &server_pub, &sec_client);

        // next_credential without prior process_reply_verf should fall back.
        let (cred, _verf) = session.next_credential();
        let body = cred.body.as_ref();
        let (decoded, _) = AuthDesCred::unpack(&mut &body[..]).expect("unpack");
        assert!(matches!(decoded, AuthDesCred::Fullname { .. }), "should fall back to fullname without nickname");
    }

    #[test]
    fn process_reply_verf_accepts_valid_response() {
        // Simulate the full flow: build credential, construct a valid
        // server reply, and verify it.
        let mut sec_client = [0u8; 24];
        sec_client[23] = 19;
        let mut sec_server = [0u8; 24];
        sec_server[23] = 23;

        let server_pub = compute_public_key(&sec_server);
        let mut session = AuthDhSession::new("unix.0@test", &server_pub, &sec_client);
        let conv_key = *session.conversation_key();

        let (_cred, _verf) = session.first_credential();

        // The server would decrypt the timestamp, subtract 1 from seconds,
        // re-encrypt, and send back with a nickname.
        let last_secs = session.last_timestamp_secs;
        let last_usecs = session.last_timestamp_usecs;

        let mut reply_ts = [0u8; 8];
        reply_ts[0..4].copy_from_slice(&(last_secs.wrapping_sub(1)).to_be_bytes());
        reply_ts[4..8].copy_from_slice(&last_usecs.to_be_bytes());
        let encrypted_reply = des_ecb_encrypt(&conv_key, &reply_ts);

        let server_verf = AuthDesVerf::Server { encrypted_timestamp_minus_one: encrypted_reply, nickname: 42 };
        let reply_auth = server_verf.to_opaque_auth();

        assert!(session.process_reply_verf(&reply_auth), "valid server verifier should be accepted");
        assert_eq!(session.server_nickname, Some(42), "nickname should be stored");
    }

    #[test]
    fn process_reply_verf_rejects_wrong_timestamp() {
        let mut sec_client = [0u8; 24];
        sec_client[23] = 29;
        let mut sec_server = [0u8; 24];
        sec_server[23] = 31;

        let server_pub = compute_public_key(&sec_server);
        let mut session = AuthDhSession::new("unix.0@test", &server_pub, &sec_client);
        let conv_key = *session.conversation_key();

        let (_cred, _verf) = session.first_credential();

        // Send back a wrong timestamp (not secs-1).
        let mut reply_ts = [0u8; 8];
        reply_ts[0..4].copy_from_slice(&999u32.to_be_bytes());
        reply_ts[4..8].copy_from_slice(&0u32.to_be_bytes());
        let encrypted_reply = des_ecb_encrypt(&conv_key, &reply_ts);

        let server_verf = AuthDesVerf::Server { encrypted_timestamp_minus_one: encrypted_reply, nickname: 1 };
        let reply_auth = server_verf.to_opaque_auth();

        assert!(!session.process_reply_verf(&reply_auth), "wrong timestamp should be rejected");
        assert_eq!(session.server_nickname, None, "nickname should not be stored on failure");
    }

    #[test]
    fn process_reply_verf_rejects_wrong_flavor() {
        let mut sec_client = [0u8; 24];
        sec_client[23] = 37;
        let mut sec_server = [0u8; 24];
        sec_server[23] = 41;

        let server_pub = compute_public_key(&sec_server);
        let mut session = AuthDhSession::new("unix.0@test", &server_pub, &sec_client);
        let (_cred, _verf) = session.first_credential();

        // AUTH_NULL flavor instead of AUTH_DES.
        let wrong_flavor = opaque_auth::default();
        assert!(!session.process_reply_verf(&wrong_flavor), "wrong flavor should be rejected");
    }

    #[test]
    fn next_credential_after_nickname_produces_nickname_cred() {
        let mut sec_client = [0u8; 24];
        sec_client[23] = 43;
        let mut sec_server = [0u8; 24];
        sec_server[23] = 47;

        let server_pub = compute_public_key(&sec_server);
        let mut session = AuthDhSession::new("unix.0@test", &server_pub, &sec_client);
        let conv_key = *session.conversation_key();

        // First credential + simulated server reply.
        let (_cred, _verf) = session.first_credential();
        let last_secs = session.last_timestamp_secs;
        let last_usecs = session.last_timestamp_usecs;

        let mut reply_ts = [0u8; 8];
        reply_ts[0..4].copy_from_slice(&(last_secs.wrapping_sub(1)).to_be_bytes());
        reply_ts[4..8].copy_from_slice(&last_usecs.to_be_bytes());
        let encrypted_reply = des_ecb_encrypt(&conv_key, &reply_ts);

        let server_verf = AuthDesVerf::Server { encrypted_timestamp_minus_one: encrypted_reply, nickname: 77 };
        assert!(session.process_reply_verf(&server_verf.to_opaque_auth()));

        // Now next_credential should produce a nickname credential.
        let (cred, verf) = session.next_credential();
        let body = cred.body.as_ref();
        let (decoded, _) = AuthDesCred::unpack(&mut &body[..]).expect("unpack");
        match decoded {
            AuthDesCred::Nickname { nickname } => assert_eq!(nickname, 77),
            AuthDesCred::Fullname { .. } => panic!("expected nickname credential after server reply"),
        }

        // Verifier should have encrypted timestamp (ECB mode).
        let verf_body = verf.body.as_ref();
        let (verf_decoded, _) = AuthDesVerf::unpack(&mut &verf_body[..]).expect("unpack verf");
        match verf_decoded {
            AuthDesVerf::Client { encrypted_timestamp, .. } => {
                // Decrypt and verify it's a valid timestamp.
                let decrypted = des_ecb_decrypt(&conv_key, &encrypted_timestamp);
                let ts_secs = u32::from_be_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]);
                let ts_usecs = u32::from_be_bytes([decrypted[4], decrypted[5], decrypted[6], decrypted[7]]);
                assert!(ts_secs > 0, "decrypted nickname timestamp seconds should be non-zero");
                assert!(ts_usecs < 1_000_000, "decrypted nickname timestamp usecs should be < 1M");
            },
            AuthDesVerf::Server { .. } => panic!("expected client verifier"),
        }
    }

    #[test]
    fn timestamp_monotonicity() {
        let mut sec_client = [0u8; 24];
        sec_client[23] = 53;
        let mut sec_server = [0u8; 24];
        sec_server[23] = 59;

        let server_pub = compute_public_key(&sec_server);
        let mut session = AuthDhSession::new("unix.0@test", &server_pub, &sec_client);

        // Force a known timestamp by calling first_credential.
        drop(session.first_credential());
        let ts1_secs = session.last_timestamp_secs;
        let ts1_usecs = session.last_timestamp_usecs;

        // Immediately call again -- wall clock might not have advanced.
        drop(session.first_credential());
        let ts2_secs = session.last_timestamp_secs;
        let ts2_usecs = session.last_timestamp_usecs;

        // Second timestamp must be strictly greater.
        assert!(ts2_secs > ts1_secs || (ts2_secs == ts1_secs && ts2_usecs > ts1_usecs), "timestamps must be strictly increasing: ({ts1_secs}, {ts1_usecs}) -> ({ts2_secs}, {ts2_usecs})");
    }

    // --- Internal arithmetic helpers ---

    #[test]
    fn from_to_be_bytes_round_trip() {
        let bytes: [u8; 24] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
        let limbs = from_be_bytes(&bytes);
        let recovered = to_be_bytes(&limbs);
        assert_eq!(bytes, recovered);
    }

    #[test]
    fn mul_wide_small_values() {
        let a: [u64; 3] = [7, 0, 0]; // 7
        let b: [u64; 3] = [11, 0, 0]; // 11
        let result = mul_wide(&a, &b);
        assert_eq!(result[0], 77); // 7 * 11
        assert_eq!(result[1], 0);
        assert_eq!(result[2], 0);
    }

    #[test]
    fn mul_wide_with_carry() {
        let a: [u64; 3] = [u64::MAX, 0, 0];
        let b: [u64; 3] = [2, 0, 0];
        let result = mul_wide(&a, &b);
        // u64::MAX * 2 = 2^65 - 2 = (1 << 64) | (2^64 - 2)
        assert_eq!(result[0], u64::MAX - 1); // lower 64 bits
        assert_eq!(result[1], 1); // carry
        assert_eq!(result[2], 0);
    }

    #[test]
    fn rem_384_by_192_small() {
        // 100 mod 7 = 2
        let dividend: [u64; 6] = [100, 0, 0, 0, 0, 0];
        let divisor: [u64; 3] = [7, 0, 0];
        let result = rem_384_by_192(&dividend, &divisor);
        assert_eq!(result[0], 2);
        assert_eq!(result[1], 0);
        assert_eq!(result[2], 0);
    }

    #[test]
    fn random_conversation_key_has_odd_parity() {
        let key = random_conversation_key();
        for (i, &byte) in key.iter().enumerate() {
            assert_eq!(byte.count_ones() % 2, 1, "byte {i} should have odd parity");
        }
    }

    #[test]
    fn set_window_overrides_default() {
        let mut sec = [0u8; 24];
        sec[23] = 1;
        let pub_key = compute_public_key(&sec);
        let mut session = AuthDhSession::new("test", &pub_key, &sec);
        session.set_window(600);

        let conv_key = *session.conversation_key();
        let (cred, verf) = session.first_credential();

        // Reconstruct the 16-byte CBC ciphertext from credential + verifier.
        let cred_body = cred.body.as_ref();
        let (cred_dec, _) = AuthDesCred::unpack(&mut &cred_body[..]).expect("unpack");
        let enc_window_bytes = match &cred_dec {
            AuthDesCred::Fullname { window, .. } => window.to_be_bytes(),
            _ => panic!("expected fullname"),
        };

        let verf_body = verf.body.as_ref();
        let (verf_dec, _) = AuthDesVerf::unpack(&mut &verf_body[..]).expect("unpack verf");
        let (enc_ts, enc_winverf) = match verf_dec {
            AuthDesVerf::Client { encrypted_timestamp, encrypted_window_verifier } => (encrypted_timestamp, encrypted_window_verifier),
            _ => panic!("expected client"),
        };

        // CBC-decrypt to recover the plaintext window value.
        let mut ciphertext = Vec::with_capacity(16);
        ciphertext.extend_from_slice(&enc_ts);
        ciphertext.extend_from_slice(&enc_window_bytes);
        ciphertext.extend_from_slice(&enc_winverf);

        let iv = [0u8; 8];
        let plaintext = des_cbc_decrypt(&conv_key, &iv, &ciphertext);
        let window = u32::from_be_bytes([plaintext[8], plaintext[9], plaintext[10], plaintext[11]]);
        let winverf = u32::from_be_bytes([plaintext[12], plaintext[13], plaintext[14], plaintext[15]]);

        assert_eq!(window, 600, "decrypted window should match set_window value");
        assert_eq!(winverf, 599, "window verifier should be window - 1");
    }
}
