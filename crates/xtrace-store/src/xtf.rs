//! Canonical XTF v1 segment encoding and verification.
//!
//! This module owns only pure bytes: it converts typed recording events into a
//! checksummed, single-frame Zstandard object and verifies those bytes again.
//! Filesystem publication and SQLite metadata remain later storage concerns.

use std::io::{BufReader, Cursor, Read as _, Write as _};

use prost::{Message as _, bytes::Bytes};
use thiserror::Error;
use xtrace_domain::ids::Id;
use xtrace_domain::{ContentHash, ProjectId, RecordingId};
use xtrace_protocol::xtf::{XtfEventEnvelope, XtfHeader};

const MAGIC: &[u8; 4] = b"XTF1";
const FOOTER_MAGIC: &[u8; 4] = b"XTFF";
const FORMAT_MAJOR: u16 = 1;
const FORMAT_MINOR: u16 = 0;
const FOOTER_BYTES: usize = 4 + (3 * 8) + 32;
const MAX_LOGICAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;
const MAX_EVENTS: usize = 2_000;
const ZSTD_LEVEL: i32 = 3;
// Four MiB is exactly 2^22, so this confines both the emitted and accepted
// zstd back-reference window to the maximum logical-stream budget.
const ZSTD_WINDOW_LOG_MAX: u32 = 22;

/// Typed input used to create one canonical XTF segment.
///
/// Sequence range and count are deliberately absent: they are derived from
/// `events` after the wrapper and nested event sequences have been verified.
pub struct XtfSegmentInput {
    /// Project that owns the segment.
    pub project_id: ProjectId,
    /// Recording that owns the segment.
    pub recording_id: RecordingId,
    /// Zero-based ordinal within the recording.
    pub segment_ordinal: u32,
    /// Ordered, typed event envelopes to encode.
    pub events: Vec<XtfEventEnvelope>,
}

/// Returns the largest compressed XTF object this codec will inspect.
///
/// The bound is Zstandard's documented worst-case `compressBound` for this
/// codec's fixed 4 MiB logical-stream limit, rather than an independently
/// chosen compressed-size budget. Future file readers can apply this limit
/// before allocating or reading an object from disk.
#[must_use]
pub fn max_compressed_segment_bytes() -> usize {
    zstd::zstd_safe::compress_bound(MAX_LOGICAL_BYTES)
}

/// Canonical XTF bytes produced from a validated [`XtfSegmentInput`].
pub struct EncodedXtfSegment {
    logical_bytes: Vec<u8>,
    compressed_bytes: Vec<u8>,
    content_hash: ContentHash,
    footer_prefix_digest: ContentHash,
    event_count: u64,
    first_recording_seq: u64,
    last_recording_seq: u64,
}

impl EncodedXtfSegment {
    /// Returns the complete uncompressed XTF stream, including its footer.
    #[must_use]
    pub fn logical_bytes(&self) -> &[u8] {
        &self.logical_bytes
    }

    /// Returns the single checksummed Zstandard frame for the logical stream.
    #[must_use]
    pub fn compressed_bytes(&self) -> &[u8] {
        &self.compressed_bytes
    }

    /// Returns the BLAKE3 address of the complete uncompressed XTF stream.
    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Returns the BLAKE3 digest stored in the footer for bytes before `XTFF`.
    ///
    /// This is deliberately distinct from [`Self::content_hash`], which
    /// addresses the complete logical stream including the footer.
    #[must_use]
    pub const fn footer_prefix_digest(&self) -> ContentHash {
        self.footer_prefix_digest
    }

    /// Returns the number of enclosed event envelopes.
    #[must_use]
    pub const fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Returns the first enclosed recording sequence number.
    #[must_use]
    pub const fn first_recording_seq(&self) -> u64 {
        self.first_recording_seq
    }

    /// Returns the last enclosed recording sequence number.
    #[must_use]
    pub const fn last_recording_seq(&self) -> u64 {
        self.last_recording_seq
    }
}

/// Metadata recovered by full verification of a compressed XTF object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedXtfSegment {
    project_id: ProjectId,
    recording_id: RecordingId,
    segment_ordinal: u32,
    content_hash: ContentHash,
    footer_prefix_digest: ContentHash,
    event_count: u64,
    first_recording_seq: u64,
    last_recording_seq: u64,
}

impl VerifiedXtfSegment {
    /// Returns the project encoded in the verified XTF header.
    #[must_use]
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Returns the recording encoded in the verified XTF header.
    #[must_use]
    pub const fn recording_id(&self) -> RecordingId {
        self.recording_id
    }

    /// Returns the verified zero-based segment ordinal.
    #[must_use]
    pub const fn segment_ordinal(&self) -> u32 {
        self.segment_ordinal
    }

    /// Returns the verified complete-logical-stream content address.
    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Returns the verified BLAKE3 digest of logical bytes before `XTFF`.
    ///
    /// Later metadata persistence can store this checksum without reparsing
    /// private footer framing.
    #[must_use]
    pub const fn footer_prefix_digest(&self) -> ContentHash {
        self.footer_prefix_digest
    }

    /// Returns the verified event count.
    #[must_use]
    pub const fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Returns the verified first recording sequence number.
    #[must_use]
    pub const fn first_recording_seq(&self) -> u64 {
        self.first_recording_seq
    }

    /// Returns the verified last recording sequence number.
    #[must_use]
    pub const fn last_recording_seq(&self) -> u64 {
        self.last_recording_seq
    }
}

/// Safe classifications for canonical XTF encoding and verification failures.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum XtfCodecError {
    /// The caller supplied no events for a segment.
    #[error("XTF segment must contain at least one event")]
    EmptyEvents,
    /// The caller supplied more events than one bounded segment supports.
    #[error("XTF segment exceeds the event limit")]
    EventLimitExceeded,
    /// An envelope has no nested `RecordingEvent` payload.
    #[error("XTF event envelope is missing its event payload")]
    MissingEvent,
    /// An envelope sequence differs from its nested event sequence.
    #[error("XTF event envelope sequence does not match nested event sequence")]
    SequenceMismatch,
    /// Event sequences are not strictly contiguous.
    #[error("XTF event sequences are not contiguous")]
    NonContiguousSequence,
    /// A contiguous sequence would exceed the `u64` range.
    #[error("XTF event sequence overflow")]
    SequenceOverflow,
    /// A bounded XTF component would exceed its allocation limit.
    #[error("XTF component exceeds its allocation limit")]
    LengthLimitExceeded,
    /// Framing ended before a complete XTF component was available.
    #[error("XTF stream is truncated")]
    Truncated,
    /// The stream does not begin with the required XTF magic bytes.
    #[error("XTF stream has invalid magic bytes")]
    InvalidMagic,
    /// The physical or protobuf format version is unsupported.
    #[error("XTF format version is unsupported")]
    UnsupportedVersion,
    /// A length-delimited protobuf component could not be decoded.
    #[error("XTF protobuf component is malformed")]
    MalformedProtobuf,
    /// A header identifier is not the required 16 bytes.
    #[error("XTF header identifier has invalid length")]
    InvalidIdentifier,
    /// Header, envelope, or footer metadata disagrees with derived values.
    #[error("XTF metadata does not match enclosed events")]
    MetadataMismatch,
    /// The footer's prefix digest does not match the preceding logical bytes.
    #[error("XTF footer digest does not match the logical prefix")]
    FooterDigestMismatch,
    /// The complete logical stream does not match the expected content address.
    #[error("XTF content address does not match expected bytes")]
    ContentAddressMismatch,
    /// The compressed object is malformed, truncated, or fails its zstd checksum.
    #[error("XTF compressed frame verification failed")]
    Compression,
    /// The compressed input contains bytes after its single zstd frame.
    #[error("XTF compressed object has trailing bytes")]
    TrailingCompressedBytes,
}

/// Encodes typed events into the canonical XTF v1 logical stream and one
/// single-threaded, checksummed Zstandard frame.
///
/// # Errors
///
/// Returns [`XtfCodecError`] when the input does not form one bounded,
/// contiguous segment or compression cannot finish successfully.
pub fn encode_segment(input: &XtfSegmentInput) -> Result<EncodedXtfSegment, XtfCodecError> {
    let logical = encode_logical_segment(input)?;
    let compressed_bytes = compress_logical_bytes(logical.logical_bytes())?;
    Ok(EncodedXtfSegment {
        logical_bytes: logical.logical_bytes,
        compressed_bytes,
        content_hash: logical.content_hash,
        footer_prefix_digest: logical.footer_prefix_digest,
        event_count: logical.event_count,
        first_recording_seq: logical.first_recording_seq,
        last_recording_seq: logical.last_recording_seq,
    })
}

/// Internal logical-stream seam used by the durable writer to order its
/// logical-file sync before compression. The public convenience encoder above
/// composes this with [`compress_logical_bytes`].
pub(crate) struct LogicalXtfSegment {
    logical_bytes: Vec<u8>,
    content_hash: ContentHash,
    footer_prefix_digest: ContentHash,
    event_count: u64,
    first_recording_seq: u64,
    last_recording_seq: u64,
}

impl LogicalXtfSegment {
    pub(crate) fn logical_bytes(&self) -> &[u8] {
        &self.logical_bytes
    }
    pub(crate) const fn content_hash(&self) -> ContentHash {
        self.content_hash
    }
    pub(crate) const fn footer_prefix_digest(&self) -> ContentHash {
        self.footer_prefix_digest
    }
    pub(crate) const fn event_count(&self) -> u64 {
        self.event_count
    }
    pub(crate) const fn first_recording_seq(&self) -> u64 {
        self.first_recording_seq
    }
    pub(crate) const fn last_recording_seq(&self) -> u64 {
        self.last_recording_seq
    }
}

pub(crate) fn encode_logical_segment(
    input: &XtfSegmentInput,
) -> Result<LogicalXtfSegment, XtfCodecError> {
    let derived = validate_events(&input.events)?;
    let header = XtfHeader {
        format_major: u32::from(FORMAT_MAJOR),
        format_minor: u32::from(FORMAT_MINOR),
        project_id: Bytes::copy_from_slice(input.project_id.as_uuid().as_bytes()),
        recording_id: Bytes::copy_from_slice(input.recording_id.as_uuid().as_bytes()),
        segment_ordinal: input.segment_ordinal,
        first_recording_seq: derived.first_recording_seq,
        last_recording_seq: derived.last_recording_seq,
        event_count: derived.event_count,
    };
    let logical = encode_logical_stream(&header, &input.events, derived)?;
    Ok(LogicalXtfSegment {
        content_hash: ContentHash::of_bytes(&logical.bytes),
        logical_bytes: logical.bytes,
        footer_prefix_digest: logical.footer_prefix_digest,
        event_count: derived.event_count,
        first_recording_seq: derived.first_recording_seq,
        last_recording_seq: derived.last_recording_seq,
    })
}

pub(crate) fn compress_logical_bytes(logical_bytes: &[u8]) -> Result<Vec<u8>, XtfCodecError> {
    compress_logical(logical_bytes, ZSTD_LEVEL)
}

#[cfg(test)]
pub(crate) fn compress_logical_at_level(
    logical_bytes: &[u8],
    level: i32,
) -> Result<Vec<u8>, XtfCodecError> {
    compress_logical(logical_bytes, level)
}

/// Fully verifies one checksummed, single-frame compressed XTF object.
///
/// # Errors
///
/// Returns [`XtfCodecError`] for malformed compression, framing, protobuf
/// payloads, event sequencing, footer integrity, or address mismatches.
pub fn verify_compressed_segment(
    compressed_bytes: &[u8],
    expected_content_hash: ContentHash,
) -> Result<VerifiedXtfSegment, XtfCodecError> {
    let logical_bytes = decompress_bounded(compressed_bytes)?;
    verify_logical_stream(&logical_bytes, expected_content_hash)
}

#[derive(Clone, Copy)]
struct DerivedEvents {
    event_count: u64,
    first_recording_seq: u64,
    last_recording_seq: u64,
}

struct LogicalXtfStream {
    bytes: Vec<u8>,
    footer_prefix_digest: ContentHash,
}

fn validate_events(events: &[XtfEventEnvelope]) -> Result<DerivedEvents, XtfCodecError> {
    if events.is_empty() {
        return Err(XtfCodecError::EmptyEvents);
    }
    if events.len() > MAX_EVENTS {
        return Err(XtfCodecError::EventLimitExceeded);
    }

    let first = event_sequence(events.first().ok_or(XtfCodecError::EmptyEvents)?)?;
    let mut previous = first;
    for envelope in &events[1..] {
        let sequence = event_sequence(envelope)?;
        let expected = previous.checked_add(1).ok_or(XtfCodecError::SequenceOverflow)?;
        if sequence != expected {
            return Err(XtfCodecError::NonContiguousSequence);
        }
        previous = sequence;
    }

    Ok(DerivedEvents {
        event_count: u64::try_from(events.len()).map_err(|_| XtfCodecError::EventLimitExceeded)?,
        first_recording_seq: first,
        last_recording_seq: previous,
    })
}

fn event_sequence(envelope: &XtfEventEnvelope) -> Result<u64, XtfCodecError> {
    let event = envelope.event.as_ref().ok_or(XtfCodecError::MissingEvent)?;
    if envelope.recording_seq != event.recording_seq {
        return Err(XtfCodecError::SequenceMismatch);
    }
    Ok(envelope.recording_seq)
}

fn encode_logical_stream(
    header: &XtfHeader,
    events: &[XtfEventEnvelope],
    derived: DerivedEvents,
) -> Result<LogicalXtfStream, XtfCodecError> {
    let header_bytes = encode_message(header, MAX_HEADER_BYTES)?;
    let mut logical =
        Vec::with_capacity(MAGIC.len() + 2 + 2 + 4 + header_bytes.len() + FOOTER_BYTES);
    logical.extend_from_slice(MAGIC);
    push_u16(&mut logical, FORMAT_MAJOR);
    push_u16(&mut logical, FORMAT_MINOR);
    push_length_prefixed(&mut logical, &header_bytes, MAX_HEADER_BYTES)?;

    for envelope in events {
        let envelope_bytes = encode_message(envelope, MAX_ENVELOPE_BYTES)?;
        push_length_prefixed(&mut logical, &envelope_bytes, MAX_ENVELOPE_BYTES)?;
    }
    ensure_logical_capacity(logical.len(), FOOTER_BYTES)?;

    // The footer digest covers the exact logical prefix before any footer byte;
    // the content address below intentionally covers the completed stream.
    let footer_prefix_digest = ContentHash::of_bytes(&logical);
    logical.extend_from_slice(FOOTER_MAGIC);
    push_u64(&mut logical, derived.event_count);
    push_u64(&mut logical, derived.first_recording_seq);
    push_u64(&mut logical, derived.last_recording_seq);
    logical.extend_from_slice(footer_prefix_digest.as_bytes());
    Ok(LogicalXtfStream { bytes: logical, footer_prefix_digest })
}

fn encode_message<M: prost::Message>(message: &M, limit: usize) -> Result<Vec<u8>, XtfCodecError> {
    let length = message.encoded_len();
    if length > limit {
        return Err(XtfCodecError::LengthLimitExceeded);
    }
    let mut bytes = Vec::with_capacity(length);
    message.encode(&mut bytes).map_err(|_| XtfCodecError::MalformedProtobuf)?;
    Ok(bytes)
}

fn push_length_prefixed(
    target: &mut Vec<u8>,
    bytes: &[u8],
    limit: usize,
) -> Result<(), XtfCodecError> {
    if bytes.len() > limit {
        return Err(XtfCodecError::LengthLimitExceeded);
    }
    ensure_logical_capacity(target.len(), 4 + bytes.len())?;
    let length = u32::try_from(bytes.len()).map_err(|_| XtfCodecError::LengthLimitExceeded)?;
    push_u32(target, length);
    target.extend_from_slice(bytes);
    Ok(())
}

fn ensure_logical_capacity(current: usize, addition: usize) -> Result<(), XtfCodecError> {
    if current.checked_add(addition).is_none_or(|length| length > MAX_LOGICAL_BYTES) {
        return Err(XtfCodecError::LengthLimitExceeded);
    }
    Ok(())
}

fn compress_logical(logical_bytes: &[u8], level: i32) -> Result<Vec<u8>, XtfCodecError> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), level)
        .map_err(|_| XtfCodecError::Compression)?;
    encoder.window_log(ZSTD_WINDOW_LOG_MAX).map_err(|_| XtfCodecError::Compression)?;
    encoder.include_checksum(true).map_err(|_| XtfCodecError::Compression)?;
    encoder.write_all(logical_bytes).map_err(|_| XtfCodecError::Compression)?;
    let compressed = encoder.finish().map_err(|_| XtfCodecError::Compression)?;
    if compressed.len() > max_compressed_segment_bytes() {
        return Err(XtfCodecError::LengthLimitExceeded);
    }
    Ok(compressed)
}

fn decompress_bounded(compressed_bytes: &[u8]) -> Result<Vec<u8>, XtfCodecError> {
    if compressed_bytes.len() > max_compressed_segment_bytes() {
        return Err(XtfCodecError::LengthLimitExceeded);
    }
    let frame_size = zstd::zstd_safe::find_frame_compressed_size(compressed_bytes)
        .map_err(|_| XtfCodecError::Compression)?;
    if frame_size != compressed_bytes.len() {
        return Err(XtfCodecError::TrailingCompressedBytes);
    }

    let reader = BufReader::new(Cursor::new(compressed_bytes));
    let mut decoder = zstd::stream::read::Decoder::with_buffer(reader)
        .map_err(|_| XtfCodecError::Compression)?
        .single_frame();
    decoder.window_log_max(ZSTD_WINDOW_LOG_MAX).map_err(|_| XtfCodecError::Compression)?;
    let mut logical = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = decoder.read(&mut buffer).map_err(|_| XtfCodecError::Compression)?;
        if read == 0 {
            return Ok(logical);
        }
        ensure_logical_capacity(logical.len(), read)?;
        logical.extend_from_slice(&buffer[..read]);
    }
}

fn verify_logical_stream(
    logical_bytes: &[u8],
    expected_content_hash: ContentHash,
) -> Result<VerifiedXtfSegment, XtfCodecError> {
    if logical_bytes.len() > MAX_LOGICAL_BYTES {
        return Err(XtfCodecError::LengthLimitExceeded);
    }
    let mut reader = LogicalReader::new(logical_bytes);
    if reader.take_exact(MAGIC.len())? != MAGIC {
        return Err(XtfCodecError::InvalidMagic);
    }
    let major = reader.read_u16()?;
    let minor = reader.read_u16()?;
    if major != FORMAT_MAJOR || minor != FORMAT_MINOR {
        return Err(XtfCodecError::UnsupportedVersion);
    }
    let header_bytes = reader.read_length_prefixed(MAX_HEADER_BYTES)?;
    let header = XtfHeader::decode(header_bytes).map_err(|_| XtfCodecError::MalformedProtobuf)?;
    let project_id = project_id_from_bytes(&header.project_id)?;
    let recording_id = recording_id_from_bytes(&header.recording_id)?;
    if header.format_major != u32::from(FORMAT_MAJOR)
        || header.format_minor != u32::from(FORMAT_MINOR)
    {
        return Err(XtfCodecError::UnsupportedVersion);
    }
    if header.event_count == 0
        || usize::try_from(header.event_count).map_or(true, |count| count > MAX_EVENTS)
    {
        return Err(XtfCodecError::MetadataMismatch);
    }

    let mut derived = None;
    loop {
        if reader.remaining().starts_with(FOOTER_MAGIC) {
            break;
        }
        let envelope_bytes = reader.read_length_prefixed(MAX_ENVELOPE_BYTES)?;
        let envelope = XtfEventEnvelope::decode(envelope_bytes)
            .map_err(|_| XtfCodecError::MalformedProtobuf)?;
        append_verified_event(&mut derived, &envelope)?;
    }
    let derived = derived.ok_or(XtfCodecError::EmptyEvents)?;
    let footer_start = reader.position();
    if reader.take_exact(FOOTER_MAGIC.len())? != FOOTER_MAGIC {
        return Err(XtfCodecError::InvalidMagic);
    }
    let footer_count = reader.read_u64()?;
    let footer_first = reader.read_u64()?;
    let footer_last = reader.read_u64()?;
    let footer_digest = reader.take_exact(32)?;
    if !reader.is_finished() {
        return Err(XtfCodecError::MetadataMismatch);
    }
    if footer_count != derived.event_count
        || footer_first != derived.first_recording_seq
        || footer_last != derived.last_recording_seq
        || header.event_count != derived.event_count
        || header.first_recording_seq != derived.first_recording_seq
        || header.last_recording_seq != derived.last_recording_seq
    {
        return Err(XtfCodecError::MetadataMismatch);
    }
    let footer_prefix_digest = ContentHash::of_bytes(&logical_bytes[..footer_start]);
    if footer_digest != footer_prefix_digest.as_bytes() {
        return Err(XtfCodecError::FooterDigestMismatch);
    }
    let content_hash = ContentHash::of_bytes(logical_bytes);
    if content_hash != expected_content_hash {
        return Err(XtfCodecError::ContentAddressMismatch);
    }

    Ok(VerifiedXtfSegment {
        project_id,
        recording_id,
        segment_ordinal: header.segment_ordinal,
        content_hash,
        footer_prefix_digest,
        event_count: derived.event_count,
        first_recording_seq: derived.first_recording_seq,
        last_recording_seq: derived.last_recording_seq,
    })
}

fn append_verified_event(
    derived: &mut Option<DerivedEvents>,
    envelope: &XtfEventEnvelope,
) -> Result<(), XtfCodecError> {
    let sequence = event_sequence(envelope)?;
    match derived {
        Some(current) => {
            if current.event_count
                >= u64::try_from(MAX_EVENTS).map_err(|_| XtfCodecError::EventLimitExceeded)?
            {
                return Err(XtfCodecError::EventLimitExceeded);
            }
            let expected =
                current.last_recording_seq.checked_add(1).ok_or(XtfCodecError::SequenceOverflow)?;
            if sequence != expected {
                return Err(XtfCodecError::NonContiguousSequence);
            }
            current.event_count += 1;
            current.last_recording_seq = sequence;
        }
        None => {
            *derived = Some(DerivedEvents {
                event_count: 1,
                first_recording_seq: sequence,
                last_recording_seq: sequence,
            });
        }
    }
    Ok(())
}

fn project_id_from_bytes(bytes: &[u8]) -> Result<ProjectId, XtfCodecError> {
    let raw: [u8; 16] = bytes.try_into().map_err(|_| XtfCodecError::InvalidIdentifier)?;
    Ok(ProjectId::from_uuid(uuid::Uuid::from_bytes(raw)))
}

fn recording_id_from_bytes(bytes: &[u8]) -> Result<RecordingId, XtfCodecError> {
    let raw: [u8; 16] = bytes.try_into().map_err(|_| XtfCodecError::InvalidIdentifier)?;
    Ok(RecordingId::from_uuid(uuid::Uuid::from_bytes(raw)))
}

fn push_u16(target: &mut Vec<u8>, value: u16) {
    target.extend_from_slice(&value.to_be_bytes());
}

fn push_u32(target: &mut Vec<u8>, value: u32) {
    target.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(target: &mut Vec<u8>, value: u64) {
    target.extend_from_slice(&value.to_be_bytes());
}

struct LogicalReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> LogicalReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.position..]
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn take_exact(&mut self, length: usize) -> Result<&'a [u8], XtfCodecError> {
        let end = self.position.checked_add(length).ok_or(XtfCodecError::Truncated)?;
        let bytes = self.bytes.get(self.position..end).ok_or(XtfCodecError::Truncated)?;
        self.position = end;
        Ok(bytes)
    }

    fn read_u16(&mut self) -> Result<u16, XtfCodecError> {
        let bytes: [u8; 2] =
            self.take_exact(2)?.try_into().map_err(|_| XtfCodecError::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, XtfCodecError> {
        let bytes: [u8; 4] =
            self.take_exact(4)?.try_into().map_err(|_| XtfCodecError::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, XtfCodecError> {
        let bytes: [u8; 8] =
            self.take_exact(8)?.try_into().map_err(|_| XtfCodecError::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_length_prefixed(&mut self, limit: usize) -> Result<&'a [u8], XtfCodecError> {
        let length =
            usize::try_from(self.read_u32()?).map_err(|_| XtfCodecError::LengthLimitExceeded)?;
        if length > limit {
            return Err(XtfCodecError::LengthLimitExceeded);
        }
        self.take_exact(length)
    }
}

#[cfg(test)]
mod tests {
    use xtrace_protocol::generated::agent::RecordingEvent;

    use super::*;

    const PROJECT_BYTES: [u8; 16] = [0x11; 16];
    const RECORDING_BYTES: [u8; 16] = [0x22; 16];

    fn project_id() -> ProjectId {
        ProjectId::from_uuid(uuid::Uuid::from_bytes(PROJECT_BYTES))
    }

    fn recording_id() -> RecordingId {
        RecordingId::from_uuid(uuid::Uuid::from_bytes(RECORDING_BYTES))
    }

    fn envelope(sequence: u64) -> XtfEventEnvelope {
        XtfEventEnvelope {
            recording_seq: sequence,
            event: Some(RecordingEvent {
                event_id: format!("event-{sequence}"),
                recording_seq: sequence,
                ..RecordingEvent::default()
            }),
        }
    }

    fn input(events: Vec<XtfEventEnvelope>) -> XtfSegmentInput {
        XtfSegmentInput {
            project_id: project_id(),
            recording_id: recording_id(),
            segment_ordinal: 7,
            events,
        }
    }

    fn encoded() -> EncodedXtfSegment {
        encode_segment(&input(vec![envelope(2), envelope(3)])).expect("encode fixture")
    }

    #[test]
    fn canonical_logical_bytes_match_the_v1_golden() {
        let segment = encoded();
        assert_eq!(
            hex::encode(segment.logical_bytes()),
            "58544631000100000000002e08011a101111111111111111111111111111111122102222222222222222222222222222222228073002380340020000000f0802120b0a076576656e742d3210020000000f0803120b0a076576656e742d33100358544646000000000000000200000000000000020000000000000003c16bf983eae30266667356ed34861d51fb02b7f50f1516b387d3fae6f73f47e3"
        );
        assert_eq!(segment.content_hash(), ContentHash::of_bytes(segment.logical_bytes()));
        assert_eq!(
            segment.footer_prefix_digest().as_bytes(),
            &segment.logical_bytes()[segment.logical_bytes().len() - 32..]
        );
        assert_eq!(
            segment.footer_prefix_digest(),
            ContentHash::of_bytes(
                &segment.logical_bytes()[..segment.logical_bytes().len() - FOOTER_BYTES]
            )
        );
    }

    #[test]
    fn round_trip_preserves_metadata_and_full_u64_sequences() {
        for sequence in [0, 2, i64::MAX as u64, i64::MAX as u64 + 1, u64::MAX] {
            let segment = encode_segment(&input(vec![envelope(sequence)]))
                .expect("encode full-range sequence");
            let verified =
                verify_compressed_segment(segment.compressed_bytes(), segment.content_hash())
                    .expect("verify full-range sequence");
            assert_eq!(verified.project_id(), project_id());
            assert_eq!(verified.recording_id(), recording_id());
            assert_eq!(verified.segment_ordinal(), 7);
            assert_eq!(verified.event_count(), 1);
            assert_eq!(verified.first_recording_seq(), sequence);
            assert_eq!(verified.last_recording_seq(), sequence);
            assert_eq!(verified.footer_prefix_digest(), segment.footer_prefix_digest());
        }
    }

    #[test]
    fn encoder_rejects_empty_missing_and_noncontiguous_events() {
        assert!(matches!(encode_segment(&input(Vec::new())), Err(XtfCodecError::EmptyEvents)));
        assert!(matches!(
            encode_segment(&input(vec![XtfEventEnvelope { recording_seq: 2, event: None }])),
            Err(XtfCodecError::MissingEvent)
        ));
        assert!(matches!(
            encode_segment(&input(vec![envelope(2), envelope(4)])),
            Err(XtfCodecError::NonContiguousSequence)
        ));
    }

    #[test]
    fn decoder_rejects_invalid_lengths_before_allocation() {
        let mut logical = Vec::new();
        logical.extend_from_slice(MAGIC);
        push_u16(&mut logical, FORMAT_MAJOR);
        push_u16(&mut logical, FORMAT_MINOR);
        push_u32(&mut logical, u32::MAX);
        let compressed = compress_logical(&logical, ZSTD_LEVEL).expect("compress malformed length");
        assert_eq!(
            verify_compressed_segment(&compressed, ContentHash::of_bytes(&logical)),
            Err(XtfCodecError::LengthLimitExceeded)
        );
    }

    #[test]
    fn compressed_input_limit_is_derived_and_rejects_only_oversize_slices() {
        let limit = max_compressed_segment_bytes();
        assert_eq!(limit, zstd::zstd_safe::compress_bound(MAX_LOGICAL_BYTES));

        let at_limit = vec![0_u8; limit];
        assert_eq!(
            verify_compressed_segment(&at_limit, ContentHash::of_bytes(b"unused")),
            Err(XtfCodecError::Compression)
        );

        let oversized = vec![0_u8; limit + 1];
        assert_eq!(
            verify_compressed_segment(&oversized, ContentHash::of_bytes(b"unused")),
            Err(XtfCodecError::LengthLimitExceeded)
        );
        assert!(encoded().compressed_bytes().len() <= limit);
    }

    #[test]
    fn rejects_sequence_range_count_footer_and_address_failures() {
        let segment = encoded();
        let header = header_from_logical(segment.logical_bytes()).expect("header");
        let mut mismatch =
            XtfEventEnvelope::decode(envelope_bytes(segment.logical_bytes(), 0).expect("event"))
                .expect("decode envelope");
        mismatch.event.as_mut().expect("event").recording_seq = 99;
        let mismatch_logical = encode_logical_stream(
            &header,
            &[mismatch],
            DerivedEvents { event_count: 1, first_recording_seq: 2, last_recording_seq: 2 },
        )
        .expect("encode sequence mismatch");
        let mismatch_compressed =
            compress_logical(&mismatch_logical.bytes, ZSTD_LEVEL).expect("compress mismatch");
        assert_eq!(
            verify_compressed_segment(
                &mismatch_compressed,
                ContentHash::of_bytes(&mismatch_logical.bytes)
            ),
            Err(XtfCodecError::SequenceMismatch)
        );

        let wrong_header = XtfHeader { event_count: 3, ..header.clone() };
        let wrong_header_logical = logical_with(wrong_header, &[envelope(2), envelope(3)]);
        let wrong_header_compressed =
            compress_logical(&wrong_header_logical, ZSTD_LEVEL).expect("compress header mismatch");
        assert_eq!(
            verify_compressed_segment(
                &wrong_header_compressed,
                ContentHash::of_bytes(&wrong_header_logical),
            ),
            Err(XtfCodecError::MetadataMismatch)
        );

        let mut footer_corrupt = segment.logical_bytes().to_vec();
        let footer_digest_offset = footer_corrupt.len() - 32;
        footer_corrupt[footer_digest_offset] ^= 0x01;
        let footer_compressed =
            compress_logical(&footer_corrupt, ZSTD_LEVEL).expect("compress footer corruption");
        assert_eq!(
            verify_compressed_segment(&footer_compressed, ContentHash::of_bytes(&footer_corrupt)),
            Err(XtfCodecError::FooterDigestMismatch)
        );
        assert_eq!(
            verify_compressed_segment(segment.compressed_bytes(), ContentHash::of_bytes(b"wrong")),
            Err(XtfCodecError::ContentAddressMismatch)
        );
    }

    #[test]
    fn decoder_rejects_version_identifier_and_footer_metadata_tampering() {
        let segment = encoded();
        let mut unsupported_version = segment.logical_bytes().to_vec();
        unsupported_version[5] = 2;
        assert_eq!(verify_logical(&unsupported_version), Err(XtfCodecError::UnsupportedVersion));

        let mut invalid_id_header = header_from_logical(segment.logical_bytes()).expect("header");
        invalid_id_header.project_id = Bytes::from_static(&[0x11; 15]);
        let invalid_id_logical = logical_with(invalid_id_header, &[envelope(2), envelope(3)]);
        assert_eq!(verify_logical(&invalid_id_logical), Err(XtfCodecError::InvalidIdentifier));

        let mut wrong_count = segment.logical_bytes().to_vec();
        let footer_start = wrong_count.len() - FOOTER_BYTES;
        wrong_count[footer_start + 4..footer_start + 12].copy_from_slice(&3_u64.to_be_bytes());
        assert_eq!(verify_logical(&wrong_count), Err(XtfCodecError::MetadataMismatch));

        let mut wrong_range = segment.logical_bytes().to_vec();
        let footer_start = wrong_range.len() - FOOTER_BYTES;
        wrong_range[footer_start + 12..footer_start + 20].copy_from_slice(&1_u64.to_be_bytes());
        assert_eq!(verify_logical(&wrong_range), Err(XtfCodecError::MetadataMismatch));
    }

    #[test]
    fn zstd_checksum_and_trailing_bytes_are_rejected() {
        let segment = encoded();
        let mut corrupted = segment.compressed_bytes().to_vec();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 0x01;
        assert_eq!(
            verify_compressed_segment(&corrupted, segment.content_hash()),
            Err(XtfCodecError::Compression)
        );

        let mut trailing = segment.compressed_bytes().to_vec();
        trailing.push(0);
        assert_eq!(
            verify_compressed_segment(&trailing, segment.content_hash()),
            Err(XtfCodecError::TrailingCompressedBytes)
        );

        let truncated = &segment.compressed_bytes()[..segment.compressed_bytes().len() - 1];
        assert_eq!(
            verify_compressed_segment(truncated, segment.content_hash()),
            Err(XtfCodecError::Compression)
        );
    }

    #[test]
    fn decoder_rejects_a_frame_with_an_excessive_window() {
        let oversized_window =
            compress_with_window(b"bounded decoder test", ZSTD_WINDOW_LOG_MAX + 1)
                .expect("construct excessive-window frame");
        assert_eq!(
            verify_compressed_segment(
                &oversized_window,
                ContentHash::of_bytes(b"bounded decoder test")
            ),
            Err(XtfCodecError::Compression)
        );
    }

    #[test]
    fn compression_level_does_not_change_logical_identity() {
        let segment = encoded();
        let lower = compress_logical(segment.logical_bytes(), 1).expect("compress at level one");
        let higher = compress_logical(segment.logical_bytes(), 9).expect("compress at level nine");
        assert_eq!(
            verify_compressed_segment(&lower, segment.content_hash())
                .expect("verify level one")
                .content_hash(),
            segment.content_hash()
        );
        assert_eq!(
            verify_compressed_segment(&higher, segment.content_hash())
                .expect("verify level nine")
                .content_hash(),
            segment.content_hash()
        );
    }

    fn header_from_logical(logical: &[u8]) -> Result<XtfHeader, XtfCodecError> {
        let mut reader = LogicalReader::new(logical);
        reader.take_exact(MAGIC.len())?;
        reader.read_u16()?;
        reader.read_u16()?;
        XtfHeader::decode(reader.read_length_prefixed(MAX_HEADER_BYTES)?)
            .map_err(|_| XtfCodecError::MalformedProtobuf)
    }

    fn envelope_bytes(logical: &[u8], index: usize) -> Result<&[u8], XtfCodecError> {
        let mut reader = LogicalReader::new(logical);
        reader.take_exact(MAGIC.len())?;
        reader.read_u16()?;
        reader.read_u16()?;
        reader.read_length_prefixed(MAX_HEADER_BYTES)?;
        for current in 0..=index {
            let bytes = reader.read_length_prefixed(MAX_ENVELOPE_BYTES)?;
            if current == index {
                return Ok(bytes);
            }
        }
        Err(XtfCodecError::Truncated)
    }

    fn logical_with(header: XtfHeader, events: &[XtfEventEnvelope]) -> Vec<u8> {
        let derived = validate_events(events).expect("valid test event sequence");
        encode_logical_stream(&header, events, derived).expect("encode test logical stream").bytes
    }

    fn verify_logical(logical: &[u8]) -> Result<VerifiedXtfSegment, XtfCodecError> {
        let compressed =
            compress_logical(logical, ZSTD_LEVEL).expect("compress test logical stream");
        verify_compressed_segment(&compressed, ContentHash::of_bytes(logical))
    }

    fn compress_with_window(bytes: &[u8], window_log: u32) -> Result<Vec<u8>, XtfCodecError> {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), ZSTD_LEVEL)
            .map_err(|_| XtfCodecError::Compression)?;
        encoder.window_log(window_log).map_err(|_| XtfCodecError::Compression)?;
        encoder.include_checksum(true).map_err(|_| XtfCodecError::Compression)?;
        encoder.write_all(bytes).map_err(|_| XtfCodecError::Compression)?;
        encoder.finish().map_err(|_| XtfCodecError::Compression)
    }
}
