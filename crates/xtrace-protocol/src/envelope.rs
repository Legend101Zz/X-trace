//! Envelope encoding, decoding, and protocol version negotiation.
//!
//! The envelope helpers wrap the generated `AgentEnvelope` type with
//! the version constants and length-prefix framing described in
//! `03b-protocol-and-api.md`. They are the only types other crates
//! should use when they need to put an envelope on the wire.

use std::convert::TryFrom;
use std::io::{self, Read, Write};

use prost::Message;
use prost::bytes::{Bytes, BytesMut};

use crate::generated::agent::{AgentEnvelope, WireMagic};

/// Current XTP-Agent protocol major version.
///
/// Bumping requires an ADR and a paired update to the cross-language
/// golden fixtures.
pub const PROTOCOL_MAJOR: u32 = 1;
/// Current XTP-Agent protocol minor version.
pub const PROTOCOL_MINOR: u32 = 0;
/// Maximum envelope size accepted on the wire. The default matches the
/// `DaemonHello` value so adapters and the daemon agree without
/// renegotiation.
pub const DEFAULT_MAX_ENVELOPE_BYTES: u32 = 1024 * 1024;
/// Maximum batch size in events.
pub const DEFAULT_MAX_BATCH_EVENTS: u32 = 256;

/// Errors raised by the envelope codec.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// The supplied buffer is larger than the negotiated envelope limit.
    #[error("envelope size {size} exceeds limit {limit}")]
    TooLarge {
        /// Actual envelope size.
        size: usize,
        /// Negotiated maximum.
        limit: u32,
    },
    /// The buffer is too short to be a valid envelope.
    #[error("buffer too short: {got} bytes")]
    Truncated {
        /// Bytes available.
        got: usize,
    },
    /// The wire magic prefix does not match the XTP-Agent envelope.
    #[error("invalid wire magic: expected XTP1")]
    BadMagic,
    /// The length-prefix is not a valid usize.
    #[error("invalid envelope length: {0}")]
    BadLength(u32),
    /// The envelope protocol version is outside the negotiated range.
    #[error(
        "protocol version {got_major}.{got_minor} outside negotiated \
         {expected_major}.0..={expected_major}.{max_minor}"
    )]
    ProtocolVersion {
        /// Major version reported by the peer.
        got_major: u32,
        /// Minor version reported by the peer.
        got_minor: u32,
        /// Major version this build negotiates.
        expected_major: u32,
        /// Highest minor this build negotiates within `expected_major`.
        max_minor: u32,
    },
    /// Protobuf decoding failed.
    #[error("decode failed: {0}")]
    Decode(#[from] prost::DecodeError),
    /// Protobuf encoding failed.
    #[error("encode failed: {0}")]
    Encode(#[from] prost::EncodeError),
    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

/// Length-delimited envelope framing.
///
/// Every envelope on the wire is a 4-byte big-endian length followed by
/// the encoded `AgentEnvelope`. The codec never trusts the announced
/// length against the negotiated envelope limit before decoding so a
/// malicious peer cannot force the daemon into a multi-gigabyte
/// allocation.
#[derive(Clone, Copy, Debug)]
pub struct EnvelopeCodec {
    /// Negotiated maximum envelope size in bytes.
    pub max_envelope_bytes: u32,
}

impl Default for EnvelopeCodec {
    fn default() -> Self {
        Self { max_envelope_bytes: DEFAULT_MAX_ENVELOPE_BYTES }
    }
}

impl EnvelopeCodec {
    /// Encodes the supplied envelope and writes its length-prefixed
    /// bytes to the writer.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::Encode`] when the protobuf encoder
    /// fails, [`EnvelopeError::TooLarge`] when the envelope exceeds
    /// the negotiated limit, or any I/O error from the underlying
    /// writer.
    pub fn write_to<W: Write>(
        &self,
        envelope: &AgentEnvelope,
        writer: &mut W,
    ) -> Result<(), EnvelopeError> {
        let mut buf = BytesMut::with_capacity(envelope.encoded_len());
        envelope.encode(&mut buf)?;
        let len = buf.len();
        let len_u32 = u32::try_from(len)
            .map_err(|_| EnvelopeError::TooLarge { size: len, limit: self.max_envelope_bytes })?;
        if len_u32 > self.max_envelope_bytes {
            return Err(EnvelopeError::TooLarge { size: len, limit: self.max_envelope_bytes });
        }
        writer.write_all(&len_u32.to_be_bytes())?;
        writer.write_all(&buf)?;
        Ok(())
    }

    /// Reads a single length-prefixed envelope from the supplied reader.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::Truncated`] when the stream ends before
    /// a complete envelope arrives, [`EnvelopeError::TooLarge`] when
    /// the announced length exceeds the negotiated envelope limit,
    /// [`EnvelopeError::Decode`] when the bytes are not a valid
    /// protobuf envelope, or any I/O error.
    pub fn read_from<R: Read>(&self, reader: &mut R) -> Result<AgentEnvelope, EnvelopeError> {
        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;
        let announced = u32::from_be_bytes(header);
        if announced > self.max_envelope_bytes {
            return Err(EnvelopeError::TooLarge {
                size: announced as usize,
                limit: self.max_envelope_bytes,
            });
        }
        let announced =
            usize::try_from(announced).map_err(|_| EnvelopeError::BadLength(announced))?;
        let mut body = vec![0u8; announced];
        if announced == 0 {
            return Err(EnvelopeError::Truncated { got: 0 });
        }
        reader.read_exact(&mut body)?;
        let envelope = AgentEnvelope::decode(body.as_slice())?;
        Ok(envelope)
    }
}

/// Validates that the supplied envelope matches the negotiated protocol
/// version and carries an allowed payload.
#[must_use = "protocol rejection is silently dropped otherwise"]
pub fn check_protocol_version(envelope: &AgentEnvelope) -> Result<(), EnvelopeError> {
    if envelope.protocol_major != PROTOCOL_MAJOR {
        return Err(EnvelopeError::ProtocolVersion {
            got_major: envelope.protocol_major,
            got_minor: envelope.protocol_minor,
            expected_major: PROTOCOL_MAJOR,
            max_minor: PROTOCOL_MINOR,
        });
    }
    if envelope.protocol_minor > PROTOCOL_MINOR {
        return Err(EnvelopeError::ProtocolVersion {
            got_major: envelope.protocol_major,
            got_minor: envelope.protocol_minor,
            expected_major: PROTOCOL_MAJOR,
            max_minor: PROTOCOL_MINOR,
        });
    }
    Ok(())
}

/// Builder for a fresh `AgentEnvelope` with the negotiated protocol
/// version, monotonic timestamp, and session identifier already filled
/// in.
#[derive(Clone, Debug)]
pub struct EnvelopeBuilder {
    /// Session identifier carried in every envelope.
    session_id: Vec<u8>,
    /// Next sequence number to assign.
    next_seq: u64,
}

impl EnvelopeBuilder {
    /// Creates a new builder for the given session.
    #[must_use]
    pub const fn new(session_id: Vec<u8>) -> Self {
        Self { session_id, next_seq: 1 }
    }

    /// Returns the next sequence number the builder will assign.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Sets the next sequence number. Used by tests that need a
    /// deterministic value.
    pub fn set_next_seq(&mut self, seq: u64) {
        self.next_seq = seq;
    }

    /// Wraps the supplied payload in a fresh `AgentEnvelope` and
    /// advances the internal sequence counter.
    pub fn build(
        &mut self,
        monotonic_ns: u64,
        message_id: &str,
        payload: xtp_payload_ctor::PayloadOneof,
    ) -> AgentEnvelope {
        let seq = self.next_seq;
        self.next_seq += 1;
        AgentEnvelope {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            runtime_session_id: Bytes::from(self.session_id.clone()),
            session_seq: seq,
            sent_monotonic_ns: monotonic_ns,
            message_id: message_id.to_string(),
            correlation_token: String::new(),
            payload: Some(payload),
        }
    }
}

/// Helper module that exposes the generated payload `oneof` so
/// callers do not need to know its nested module path.
pub mod xtp_payload_ctor {
    pub use crate::generated::agent::agent_envelope::Payload as PayloadOneof;
}

/// Computes the XTP1 wire magic as a `u32` for diagnostic output.
#[must_use]
pub fn wire_magic_word() -> u32 {
    WireMagic::Xtp1 as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::agent::Health;

    #[test]
    fn codec_round_trips_envelope() {
        let codec = EnvelopeCodec::default();
        let mut builder = EnvelopeBuilder::new(vec![0xab; 16]);
        let envelope = builder.build(
            123,
            "msg-1",
            xtp_payload_ctor::PayloadOneof::Health(Health {
                monotonic_ns: 123,
                queue_depth_batches: 0,
                resident_bytes: 0,
                status: "ok".to_string(),
            }),
        );
        let mut buf = Vec::new();
        codec.write_to(&envelope, &mut buf).expect("encode");
        let mut slice = buf.as_slice();
        let decoded = codec.read_from(&mut slice).expect("decode");
        assert_eq!(decoded.protocol_major, PROTOCOL_MAJOR);
        assert_eq!(decoded.protocol_minor, PROTOCOL_MINOR);
        assert_eq!(decoded.session_seq, 1);
        assert!(decoded.payload.is_some());
    }

    #[test]
    fn codec_rejects_oversize_envelope() {
        let codec = EnvelopeCodec { max_envelope_bytes: 16 };
        let mut builder = EnvelopeBuilder::new(vec![0; 16]);
        let envelope = builder.build(
            0,
            "msg",
            xtp_payload_ctor::PayloadOneof::Health(Health {
                monotonic_ns: 0,
                queue_depth_batches: 0,
                resident_bytes: 0,
                status: "x".repeat(64),
            }),
        );
        let mut buf = Vec::new();
        let err = codec.write_to(&envelope, &mut buf).unwrap_err();
        assert!(matches!(err, EnvelopeError::TooLarge { .. }));
    }

    #[test]
    fn version_check_rejects_major_mismatch() {
        let mut builder = EnvelopeBuilder::new(vec![0; 16]);
        let mut envelope = builder.build(
            0,
            "msg",
            xtp_payload_ctor::PayloadOneof::Health(Health {
                monotonic_ns: 0,
                queue_depth_batches: 0,
                resident_bytes: 0,
                status: String::new(),
            }),
        );
        envelope.protocol_major = PROTOCOL_MAJOR + 1;
        let err = check_protocol_version(&envelope).unwrap_err();
        assert!(matches!(
            err,
            EnvelopeError::ProtocolVersion {
                got_major: m,
                expected_major: PROTOCOL_MAJOR,
                ..
            } if m == PROTOCOL_MAJOR + 1
        ));
    }
}
