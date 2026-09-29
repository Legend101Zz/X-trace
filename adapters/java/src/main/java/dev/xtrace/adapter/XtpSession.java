package dev.xtrace.adapter;

import com.google.protobuf.ByteString;
import com.google.protobuf.Message;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.Semaphore;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.crypto.digests.Blake3Digest;
import org.conscrypt.Conscrypt;
import xtp.agent.v1.CapabilityOuterClass.CapabilitySet;
import xtp.agent.v1.Envelope.AgentEnvelope;
import xtp.agent.v1.Handshake.AdapterHello;
import xtp.agent.v1.Handshake.DaemonHello;
import xtp.agent.v1.Recording.EventBatch;
import xtp.agent.v1.Recording.RecordingFinished;
import xtp.agent.v1.Recording.RecordingStarted;
import xtp.agent.v1.Transport.Ack;
import xtp.agent.v1.Transport.AckDurability;

/** Authenticated, sequential XTP session over a pinned Conscrypt TLS 1.3 connection. */
public final class XtpSession implements AutoCloseable {
  private static final String EXPORTER_LABEL = "xtrace-adapter-transport-v1";
  private static final int TIMEOUT_MILLIS = 5_000;
  private static final int MAX_PENDING_SENDS = 64;
  private static final int MAX_MANIFEST_BYTES = 64 * 1024;
  private static final Pattern CANONICAL_PIN = Pattern.compile("[0-9a-f]{64}");

  private final SSLSocket socket;
  private final InputStream input;
  private final OutputStream output;
  private final byte[] runtimeSessionId;
  private final int protocolMajor;
  private final int protocolMinor;
  private final int maxEnvelopeBytes;
  private final InboundEnvelopeValidator inboundValidator;
  private final ReentrantLock sendLock = new ReentrantLock(true);
  private final Semaphore pending = new Semaphore(MAX_PENDING_SENDS, true);
  private long nextSequence = 1;
  private boolean closed;

  private XtpSession(
      SSLSocket socket,
      byte[] runtimeSessionId,
      int protocolMajor,
      int protocolMinor,
      int maxEnvelopeBytes)
      throws IOException {
    this.socket = socket;
    this.input = socket.getInputStream();
    this.output = socket.getOutputStream();
    this.runtimeSessionId = runtimeSessionId;
    this.protocolMajor = protocolMajor;
    this.protocolMinor = protocolMinor;
    this.maxEnvelopeBytes = maxEnvelopeBytes;
    this.inboundValidator =
        new InboundEnvelopeValidator(runtimeSessionId, protocolMajor, protocolMinor);
  }

  /**
   * Connects, verifies the exact leaf certificate pin, exports TLS keying material, and completes
   * the canonical XTP hello exchange. No XTP application bytes are written before pin validation.
   */
  public static XtpSession open(Bootstrap bootstrap, byte[] manifestBytes, ClientIdentity identity)
      throws ClientException {
    SSLSocket socket = null;
    byte[] secret = bootstrap.copySessionSecret();
    byte[] clientNonce = new byte[32];
    byte[] exporter = null;
    try {
      if (manifestBytes.length > MAX_MANIFEST_BYTES) {
        throw new ClientException("XTR-JAVA-MANIFEST", "adapter manifest exceeds the allowed size");
      }
      String manifestDigest = "b3:" + HexFormat.of().formatHex(blake3(manifestBytes));
      new SecureRandom().nextBytes(clientNonce);
      byte[] sessionId = Identifiers.uuidBytes(bootstrap.runtimeSessionId());

      SSLContext context = SSLContext.getInstance("TLS", Conscrypt.newProvider());
      context.init(null, new TrustManager[] {new PinDeferredTrustManager()}, new SecureRandom());
      socket = (SSLSocket) context.getSocketFactory().createSocket();
      socket.setEnabledProtocols(new String[] {"TLSv1.3"});
      socket.setSoTimeout(TIMEOUT_MILLIS);
      socket.connect(new InetSocketAddress(bootstrap.host(), bootstrap.port()), TIMEOUT_MILLIS);
      socket.startHandshake();
      verifyCertificatePin(
          bootstrap.certificatePin(), socket.getSession().getPeerCertificates()[0].getEncoded());

      exporter = Conscrypt.exportKeyingMaterial(socket, EXPORTER_LABEL, new byte[0], 32);
      byte[] inboundProof =
          TranscriptProof.compute(
              secret,
              exporter,
              sessionId,
              clientNonce,
              TranscriptProof.zeroNonce(),
              manifestDigest.getBytes(StandardCharsets.UTF_8));
      AgentEnvelope hello =
          AgentEnvelope.newBuilder()
              .setProtocolMajor(bootstrap.protocolMajor())
              .setProtocolMinor(bootstrap.protocolMinor())
              .setRuntimeSessionId(ByteString.copyFrom(sessionId))
              .setSessionSeq(0)
              .setSentMonotonicNs(System.nanoTime())
              .setMessageId("java-synthetic-hello")
              .setCorrelationToken("")
              .setAdapterHello(
                  AdapterHello.newBuilder()
                      .setAdapterName(identity.adapterName())
                      .setAdapterVersion(identity.adapterVersion())
                      .setManifestDigest(manifestDigest)
                      .setLanguage(identity.language())
                      .setRuntimeName(identity.runtimeName())
                      .setRuntimeVersion(identity.runtimeVersion())
                      .setPid(identity.pid())
                      .setProcessStartMonotonicNs(identity.processStartMonotonicNs())
                      .setRepositoryFingerprint(bootstrap.repositoryFingerprint())
                      .setProtocolMajorMax(bootstrap.protocolMajor())
                      .setProtocolMinorMax(bootstrap.protocolMinor())
                      .setClientNonce(ByteString.copyFrom(clientNonce))
                      .setHmac(ByteString.copyFrom(inboundProof)))
              .build();
      OutputStream output = socket.getOutputStream();
      InputStream input = socket.getInputStream();
      Framing.write(output, hello, Framing.HELLO_MAX_ENVELOPE_BYTES);
      AgentEnvelope response = Framing.read(input, Framing.HELLO_MAX_ENVELOPE_BYTES);
      InboundEnvelopeValidator.validateHello(response, sessionId);
      DaemonHello daemon = response.getDaemonHello();
      if (daemon.getProtocolMajor() != bootstrap.protocolMajor()
          || daemon.getProtocolMinor() > bootstrap.protocolMinor()
          || response.getProtocolMajor() != daemon.getProtocolMajor()
          || response.getProtocolMinor() != daemon.getProtocolMinor()
          || !daemon.getManifestDigest().equals(manifestDigest)
          || daemon.getServerNonce().size() != 32) {
        throw new ClientException("XTR-JAVA-HANDSHAKE", "daemon hello negotiation is invalid");
      }
      byte[] expected =
          TranscriptProof.compute(
              secret,
              exporter,
              sessionId,
              clientNonce,
              daemon.getServerNonce().toByteArray(),
              manifestDigest.getBytes(StandardCharsets.UTF_8));
      TranscriptProof.verify(expected, daemon.getHmac().toByteArray());
      int maximum = daemon.getMaxEnvelopeBytes();
      if (maximum < 1
          || maximum > Framing.ABSOLUTE_MAX_ENVELOPE_BYTES
          || daemon.getMaxBatchEvents() < 1) {
        throw new ClientException("XTR-JAVA-HANDSHAKE", "daemon limits are invalid");
      }
      XtpSession session =
          new XtpSession(
              socket, sessionId, daemon.getProtocolMajor(), daemon.getProtocolMinor(), maximum);
      socket = null;
      return session;
    } catch (ClientException error) {
      throw error;
    } catch (IOException | GeneralSecurityException error) {
      throw new ClientException("XTR-JAVA-CONNECT", "daemon TLS connection failed", error);
    } catch (LinkageError error) {
      throw new ClientException(
          "XTR-JAVA-CONNECT", "daemon TLS support could not be initialized", error);
    } finally {
      Arrays.fill(secret, (byte) 0);
      Arrays.fill(clientNonce, (byte) 0);
      if (exporter != null) Arrays.fill(exporter, (byte) 0);
      if (socket != null) closeQuietly(socket);
    }
  }

  /**
   * Sends one payload in invocation order and waits for its exact contiguous Staged ACK. More than
   * 64 concurrent callers are rejected rather than queued without bound.
   */
  public Ack send(String messageId, String correlationToken, Message payload)
      throws ClientException {
    if (messageId == null || messageId.isEmpty()) {
      throw new ClientException("XTR-JAVA-ENVELOPE", "message ID must not be empty");
    }
    if (!pending.tryAcquire()) {
      throw new ClientException("XTR-JAVA-QUEUE", "XTP send queue is full");
    }
    try {
      sendLock.lock();
      try {
        ensureOpen();
        long sequence = nextSequence;
        // Generated Java uint64 fields use signed long. Fail before emitting the final
        // positive value rather than wrapping and making an already-staged send ambiguous.
        if (sequence == Long.MAX_VALUE) {
          throw new ClientException("XTR-JAVA-SEQUENCE", "session sequence is exhausted");
        }
        AgentEnvelope.Builder builder =
            AgentEnvelope.newBuilder()
                .setProtocolMajor(protocolMajor)
                .setProtocolMinor(protocolMinor)
                .setRuntimeSessionId(ByteString.copyFrom(runtimeSessionId))
                .setSessionSeq(sequence)
                .setSentMonotonicNs(System.nanoTime())
                .setMessageId(messageId)
                .setCorrelationToken(correlationToken == null ? "" : correlationToken);
        setPayload(builder, payload);
        Framing.write(output, builder.build(), maxEnvelopeBytes);
        AgentEnvelope response = nextNonHealth();
        validateAck(response, sequence);
        nextSequence = sequence + 1;
        return response.getAck();
      } catch (ClientException | RuntimeException error) {
        failClosed();
        if (error instanceof ClientException clientError) throw clientError;
        throw new ClientException("XTR-JAVA-TRANSPORT", "XTP send failed safely", error);
      } finally {
        sendLock.unlock();
      }
    } finally {
      pending.release();
    }
  }

  private static void setPayload(AgentEnvelope.Builder envelope, Message payload)
      throws ClientException {
    if (payload instanceof CapabilitySet value) envelope.setCapabilitySet(value);
    else if (payload instanceof RecordingStarted value) envelope.setRecordingStarted(value);
    else if (payload instanceof EventBatch value) envelope.setEventBatch(value);
    else if (payload instanceof RecordingFinished value) envelope.setRecordingFinished(value);
    else throw new ClientException("XTR-JAVA-ENVELOPE", "outgoing payload type is unsupported");
  }

  private AgentEnvelope nextNonHealth() throws ClientException {
    for (int count = 0; count < 16; count++) {
      AgentEnvelope envelope = Framing.read(input, maxEnvelopeBytes);
      inboundValidator.accept(envelope);
      if (envelope.getPayloadCase() != AgentEnvelope.PayloadCase.HEALTH) return envelope;
    }
    throw new ClientException(
        "XTR-JAVA-TRANSPORT", "daemon sent too many unsolicited health frames");
  }

  private void validateAck(AgentEnvelope response, long sequence) throws ClientException {
    if (!response.getRuntimeSessionId().equals(ByteString.copyFrom(runtimeSessionId))
        || response.getProtocolMajor() != protocolMajor
        || response.getProtocolMinor() != protocolMinor
        || response.getPayloadCase() != AgentEnvelope.PayloadCase.ACK
        || response.getAck().getDurability() != AckDurability.ACK_DURABILITY_STAGED
        || response.getAck().getHighestContiguousSessionSeq() != sequence
        || response.getAck().getRejectedCount() != 0) {
      throw new ClientException(
          "XTR-JAVA-ACK", "daemon did not stage session sequence " + sequence);
    }
  }

  /** Verifies the exact SHA-256 digest of the daemon leaf certificate DER bytes. */
  public static void verifyCertificatePin(String expectedHex, byte[] certificateDer)
      throws ClientException {
    try {
      if (expectedHex == null
          || certificateDer == null
          || !CANONICAL_PIN.matcher(expectedHex).matches()) {
        throw new ClientException(
            "XTR-JAVA-TLS-PIN", "daemon certificate pin did not match bootstrap");
      }
      byte[] expected = HexFormat.of().parseHex(expectedHex);
      byte[] actual = MessageDigest.getInstance("SHA-256").digest(certificateDer);
      if (expected.length != 32 || !MessageDigest.isEqual(expected, actual)) {
        throw new ClientException(
            "XTR-JAVA-TLS-PIN", "daemon certificate pin did not match bootstrap");
      }
    } catch (IllegalArgumentException | GeneralSecurityException error) {
      throw new ClientException(
          "XTR-JAVA-TLS-PIN", "daemon certificate pin did not match bootstrap", error);
    }
  }

  private static byte[] blake3(byte[] bytes) {
    Blake3Digest digest = new Blake3Digest(256);
    digest.update(bytes, 0, bytes.length);
    byte[] output = new byte[32];
    digest.doFinal(output, 0);
    return output;
  }

  private void ensureOpen() throws ClientException {
    if (closed) throw new ClientException("XTR-JAVA-TRANSPORT", "XTP session is closed");
  }

  private void failClosed() {
    closed = true;
    closeQuietly(socket);
  }

  /** Sends TLS close-notify and releases the connection after the active send completes. */
  @Override
  public void close() throws ClientException {
    sendLock.lock();
    try {
      if (closed) return;
      closed = true;
      try {
        socket.close();
      } catch (IOException error) {
        throw new ClientException("XTR-JAVA-TRANSPORT", "XTP session close failed", error);
      }
    } finally {
      sendLock.unlock();
    }
  }

  private static void closeQuietly(SSLSocket socket) {
    try {
      socket.close();
    } catch (IOException ignored) {
      /* best-effort failure cleanup */
    }
  }

  /** Public identity fields incorporated into AdapterHello. */
  public record ClientIdentity(
      String adapterName,
      String adapterVersion,
      String language,
      String runtimeName,
      String runtimeVersion,
      long pid,
      long processStartMonotonicNs) {
    /** Validates the non-secret identity values before any connection attempt. */
    public ClientIdentity {
      if (adapterName == null
          || adapterName.isBlank()
          || adapterVersion == null
          || adapterVersion.isBlank()
          || language == null
          || language.isBlank()
          || runtimeName == null
          || runtimeName.isBlank()
          || runtimeVersion == null
          || runtimeVersion.isBlank()
          || pid < 0) {
        throw new IllegalArgumentException("client identity fields are invalid");
      }
    }
  }

  // Certificate-chain validation is intentionally deferred to the exact bootstrap pin. The
  // trust manager is scoped to this SSLContext and never installed as a process-global provider.
  private static final class PinDeferredTrustManager implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
      throw new CertificateException("client certificates are not accepted");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
      if (chain == null || chain.length == 0)
        throw new CertificateException("server certificate is missing");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }
}
