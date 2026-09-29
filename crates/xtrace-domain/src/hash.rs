//! Content hashing primitives.
//!
//! X-trace uses BLAKE3-256 for all content identities. Hashes are tagged
//! with their algorithm (`b3:...`) so a future migration to another
//! algorithm can coexist with archived data.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

const BLAKE3_PREFIX: &str = "b3:";

/// 256-bit content hash tagged with its algorithm.
///
/// Persisted as a 32-byte blob in SQLite and as the lowercase
/// `b3:<hex>` form on the wire. `FromStr` accepts uppercase hex
/// digits because the underlying hex decoder is case-insensitive;
/// callers comparing wire input against `to_canonical` must do an
/// exact string equality check rather than rely on round-trip
/// parsing.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct ContentHash(#[serde(with = "hex_serde")] [u8; 32]);

impl ContentHash {
    /// Computes a content hash over the supplied bytes.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let digest = blake3::hash(bytes);
        Self(*digest.as_bytes())
    }

    /// Wraps an already-computed BLAKE3-256 digest. Used by callers
    /// that build the digest incrementally through a
    /// [`blake3::Hasher`] and only need to tag the result.
    #[must_use]
    pub const fn from_blake3_digest(digest: blake3::Hash) -> Self {
        Self(*digest.as_bytes())
    }

    /// Returns the raw 32-byte digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Renders the canonical `b3:<lowercase hex>` form. Callers
    /// comparing wire input against this output must do an exact
    /// string comparison; `ContentHash::from_str` accepts uppercase
    /// hex digits so byte-equality is the only reliable equality
    /// check across the parse boundary.
    #[must_use]
    pub fn to_canonical(&self) -> String {
        let mut out = String::with_capacity(3 + 64);
        out.push_str(BLAKE3_PREFIX);
        for byte in &self.0 {
            use std::fmt::Write as _;
            let _ = write!(&mut out, "{byte:02x}");
        }
        out
    }
}

impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_canonical())
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_canonical())
    }
}

impl FromStr for ContentHash {
    type Err = HashParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s.strip_prefix(BLAKE3_PREFIX).ok_or(HashParseError::Prefix)?;
        if hex.len() != 64 {
            return Err(HashParseError::Length);
        }
        let bytes = hex::decode(hex).map_err(|e| HashParseError::Hex(e.to_string()))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

/// Errors raised when parsing a content hash string.
///
/// `hex::FromHexError` does not implement `std::error::Error` so the
/// `Hex` variant stores a description string instead of a source chain.
#[derive(Debug, thiserror::Error)]
pub enum HashParseError {
    /// Missing or wrong algorithm prefix.
    #[error("content hash must start with 'b3:'")]
    Prefix,
    /// Wrong encoded length.
    #[error("content hash must be 32 bytes")]
    Length,
    /// Invalid hexadecimal.
    #[error("invalid hex encoding: {0}")]
    Hex(String),
}

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode_upper(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("hash must decode to 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_hash_is_deterministic() {
        let a = ContentHash::of_bytes(b"xtrace");
        let b = ContentHash::of_bytes(b"xtrace");
        assert_eq!(a, b);
    }

    #[test]
    fn from_blake3_digest_matches_of_bytes() {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"xtrace");
        let from_hasher = ContentHash::from_blake3_digest(hasher.finalize());
        let from_bytes = ContentHash::of_bytes(b"xtrace");
        assert_eq!(from_hasher, from_bytes);
    }

    #[test]
    fn canonical_form_round_trips() {
        let h = ContentHash::of_bytes(b"hello world");
        let s = h.to_canonical();
        assert!(s.starts_with("b3:"));
        let parsed: ContentHash = s.parse().expect("parses");
        assert_eq!(parsed, h);
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let err = "deadbeef".parse::<ContentHash>().unwrap_err();
        assert!(matches!(err, HashParseError::Prefix));
    }
}
