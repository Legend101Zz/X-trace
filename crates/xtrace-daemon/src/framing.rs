//! Length-delimited envelope framing for the daemon side.
//!
//! The wire format is defined in `docs/plans/x-trace/03b-protocol-and-api.md`
//! §2.2:
//!
//! ```text
//! 4-byte big-endian length  ||  encoded AgentEnvelope protobuf
//! ```
//!
//! The codec refuses to allocate or read beyond the negotiated
//! [`crate::DaemonConfig::max_envelope_bytes`] so a malicious peer
//! cannot force the daemon into a multi-gigabyte allocation. The
//! framing layer never parses protobuf beyond the size check; that
//! lives in [`xtrace_protocol::envelope`].

use std::io::{self, Read, Write};

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use xtrace_protocol::envelope::EnvelopeCodec;
use xtrace_protocol::generated::agent::AgentEnvelope;

/// Synchronous encoder used by tests and the protobuf round-trip
/// suite. Production daemon code uses the [`EnvelopeAsyncEncoder`]
/// variant because the supervisor runs on tokio.
pub struct EnvelopeEncoder<'a, W> {
    codec: EnvelopeCodec,
    writer: &'a mut W,
}

impl<'a, W: Write> EnvelopeEncoder<'a, W> {
    /// Constructs an encoder bound to the supplied writer.
    #[must_use]
    pub const fn new(writer: &'a mut W, max_envelope_bytes: u32) -> Self {
        Self { codec: EnvelopeCodec { max_envelope_bytes }, writer }
    }

    /// Writes a single length-prefixed envelope.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the underlying writer fails, the
    /// envelope exceeds the negotiated limit, or the protobuf
    /// encoder reports an error.
    pub fn write_envelope(&mut self, envelope: &AgentEnvelope) -> io::Result<()> {
        let mut buf = Vec::with_capacity(envelope.encoded_len());
        envelope
            .encode(&mut buf)
            .map_err(|err| io::Error::other(format!("encode envelope: {err}")))?;
        let len = u32::try_from(buf.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("envelope length {} does not fit in u32", buf.len()),
            )
        })?;
        if len > self.codec.max_envelope_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("envelope length {len} exceeds limit {}", self.codec.max_envelope_bytes),
            ));
        }
        self.writer.write_all(&len.to_be_bytes())?;
        self.writer.write_all(&buf)?;
        Ok(())
    }
}

/// Synchronous decoder used by tests.
pub struct EnvelopeDecoder<'a, R> {
    codec: EnvelopeCodec,
    reader: &'a mut R,
}

impl<'a, R: Read> EnvelopeDecoder<'a, R> {
    /// Constructs a decoder bound to the supplied reader.
    #[must_use]
    pub const fn new(reader: &'a mut R, max_envelope_bytes: u32) -> Self {
        Self { codec: EnvelopeCodec { max_envelope_bytes }, reader }
    }

    /// Reads a single length-prefixed envelope.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the reader reports an I/O failure,
    /// the stream ends mid-envelope, the announced length exceeds the
    /// negotiated limit, or the protobuf decoder rejects the bytes.
    pub fn read_envelope(&mut self) -> io::Result<AgentEnvelope> {
        self.codec.read_from(&mut self.reader).map_err(map_envelope_error)
    }
}

fn map_envelope_error(err: xtrace_protocol::envelope::EnvelopeError) -> io::Error {
    use xtrace_protocol::envelope::EnvelopeError as E;
    match &err {
        E::TooLarge { .. } | E::BadLength(_) | E::BadMagic => {
            io::Error::new(io::ErrorKind::InvalidData, format!("read envelope: {err}"))
        }
        E::Truncated { .. } => {
            io::Error::new(io::ErrorKind::UnexpectedEof, format!("read envelope: {err}"))
        }
        E::ProtocolVersion { .. } => {
            io::Error::new(io::ErrorKind::InvalidData, format!("read envelope: {err}"))
        }
        E::Decode(_) | E::Encode(_) | E::Io(_) => io::Error::other(format!("read envelope: {err}")),
    }
}

/// Asynchronous envelope encoder. Mirrors [`EnvelopeEncoder`] but
/// operates on [`AsyncWrite`] so the daemon can write to a TLS stream
/// without buffering the whole envelope in memory.
pub struct EnvelopeAsyncEncoder<W> {
    codec: EnvelopeCodec,
    writer: W,
}

impl<W: AsyncWrite + Unpin> EnvelopeAsyncEncoder<W> {
    /// Constructs an asynchronous encoder bound to the supplied
    /// writer.
    #[must_use]
    pub const fn new(writer: W, max_envelope_bytes: u32) -> Self {
        Self { codec: EnvelopeCodec { max_envelope_bytes }, writer }
    }

    /// Returns a mutable reference to the inner writer.
    pub fn writer_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Writes a single length-prefixed envelope.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the underlying writer fails, the
    /// envelope exceeds the negotiated limit, or the protobuf
    /// encoder reports an error.
    pub async fn write_envelope(&mut self, envelope: &AgentEnvelope) -> io::Result<()> {
        let encoded_len = envelope.encoded_len();
        let len = u32::try_from(encoded_len).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("envelope length {encoded_len} does not fit in u32"),
            )
        })?;
        if len > self.codec.max_envelope_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("envelope length {len} exceeds limit {}", self.codec.max_envelope_bytes),
            ));
        }
        // Stop-and-wait clients need the entire ACK before they can send again.
        // Give TLS the prefix and body together so the prefix is not sent on its own.
        let mut frame = Vec::with_capacity(encoded_len + size_of::<u32>());
        frame.extend_from_slice(&len.to_be_bytes());
        envelope
            .encode(&mut frame)
            .map_err(|err| io::Error::other(format!("encode envelope: {err}")))?;
        self.writer.write_all(&frame).await?;
        // TLS may buffer writes; peers can wait for this frame before sending more.
        self.writer.flush().await
    }
}

/// Asynchronous envelope decoder. Mirrors [`EnvelopeDecoder`] but
/// operates on [`AsyncRead`].
pub struct EnvelopeAsyncDecoder<R> {
    codec: EnvelopeCodec,
    reader: R,
}

impl<R: AsyncRead + Unpin> EnvelopeAsyncDecoder<R> {
    /// Constructs an asynchronous decoder bound to the supplied
    /// reader.
    #[must_use]
    pub const fn new(reader: R, max_envelope_bytes: u32) -> Self {
        Self { codec: EnvelopeCodec { max_envelope_bytes }, reader }
    }

    /// Reads a single length-prefixed envelope.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the reader reports an I/O failure,
    /// the stream ends mid-envelope, the announced length exceeds the
    /// negotiated limit, or the protobuf decoder rejects the bytes.
    pub async fn read_envelope(&mut self) -> io::Result<AgentEnvelope> {
        let mut header = [0u8; 4];
        self.reader.read_exact(&mut header).await?;
        let announced = u32::from_be_bytes(header);
        if announced > self.codec.max_envelope_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "envelope length {announced} exceeds limit {}",
                    self.codec.max_envelope_bytes
                ),
            ));
        }
        let announced = usize::try_from(announced)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid length"))?;
        if announced == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty envelope"));
        }
        let mut body = vec![0u8; announced];
        self.reader.read_exact(&mut body).await?;
        AgentEnvelope::decode(body.as_slice())
            .map_err(|err| io::Error::other(format!("decode envelope: {err}")))
    }
}

#[cfg(test)]
pub(crate) mod test_writer {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::AsyncWrite;

    #[derive(Default)]
    pub(crate) struct BufferedWriter {
        pub(crate) pending: Vec<u8>,
        pub(crate) write_count: usize,
        pub(crate) delivered: Vec<u8>,
        pub(crate) fail_flush: bool,
        pub(crate) hold_flush: Option<std::sync::Arc<tokio::sync::Notify>>,
    }

    impl AsyncWrite for BufferedWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.write_count += 1;
            self.pending.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            if let Some(entered) = &self.hold_flush {
                entered.notify_one();
                return Poll::Pending;
            }
            if self.fail_flush {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "flush failed")));
            }
            let pending = std::mem::take(&mut self.pending);
            self.delivered.extend_from_slice(&pending);
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xtrace_protocol::envelope::{EnvelopeBuilder, xtp_payload_ctor};
    use xtrace_protocol::generated::agent::Health;

    fn sample_envelope() -> AgentEnvelope {
        let mut builder = EnvelopeBuilder::new(vec![0xab; 16]);
        builder.build(
            7,
            "msg-1",
            xtp_payload_ctor::PayloadOneof::Health(Health {
                monotonic_ns: 7,
                queue_depth_batches: 0,
                resident_bytes: 0,
                status: "ok".to_string(),
            }),
        )
    }

    #[tokio::test]
    async fn async_ack_flushes_the_complete_frame_and_propagates_flush_errors() {
        use super::test_writer::BufferedWriter;
        let envelope = AgentEnvelope {
            payload: Some(xtp_payload_ctor::PayloadOneof::Ack(Default::default())),
            ..Default::default()
        };
        let mut encoder = EnvelopeAsyncEncoder::new(BufferedWriter::default(), 1024);
        encoder.write_envelope(&envelope).await.expect("write ACK");
        let writer = encoder.writer_mut();
        assert!(writer.pending.is_empty());
        assert_eq!(writer.write_count, 1, "offer the complete ACK to TLS in one write");
        let mut reader = writer.delivered.as_slice();
        let decoded =
            EnvelopeDecoder::new(&mut reader, 1024).read_envelope().expect("complete frame");
        assert!(matches!(decoded.payload, Some(xtp_payload_ctor::PayloadOneof::Ack(_))));
        assert!(reader.is_empty());

        let mut encoder = EnvelopeAsyncEncoder::new(
            BufferedWriter { fail_flush: true, ..Default::default() },
            1024,
        );
        assert_eq!(
            encoder.write_envelope(&envelope).await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn encoder_writes_decoder_reads() {
        let envelope = sample_envelope();
        let mut buf = Vec::new();
        {
            let mut encoder = EnvelopeEncoder::new(&mut buf, 1024 * 1024);
            encoder.write_envelope(&envelope).expect("write");
        }
        let mut cursor = buf.as_slice();
        let mut decoder = EnvelopeDecoder::new(&mut cursor, 1024 * 1024);
        let decoded = decoder.read_envelope().expect("read");
        assert_eq!(decoded.message_id, envelope.message_id);
        assert_eq!(decoded.session_seq, envelope.session_seq);
    }

    #[test]
    fn encoder_refuses_oversize_envelope() {
        let mut envelope = sample_envelope();
        if let Some(xtp_payload_ctor::PayloadOneof::Health(h)) = envelope.payload.as_mut() {
            h.status = "x".repeat(64);
        }
        let mut buf = Vec::new();
        let err = EnvelopeEncoder::new(&mut buf, 16).write_envelope(&envelope).unwrap_err();
        assert!(matches!(err.kind(), io::ErrorKind::InvalidData));
    }

    #[test]
    fn decoder_refuses_oversize_length_prefix() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::to_be_bytes(u32::MAX));
        let mut cursor = buf.as_slice();
        let err = EnvelopeDecoder::new(&mut cursor, 1024).read_envelope().unwrap_err();
        assert!(matches!(err.kind(), io::ErrorKind::InvalidData));
    }
}
