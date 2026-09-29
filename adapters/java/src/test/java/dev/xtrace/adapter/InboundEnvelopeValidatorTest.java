package dev.xtrace.adapter;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.google.protobuf.ByteString;
import org.junit.jupiter.api.Test;
import xtp.agent.v1.Envelope.AgentEnvelope;
import xtp.agent.v1.Handshake.DaemonHello;
import xtp.agent.v1.Transport.Ack;
import xtp.agent.v1.Transport.Health;

final class InboundEnvelopeValidatorTest {
  private static final byte[] SESSION = new byte[16];

  @Test
  void acceptsIndependentlySequencedHealthThenAck() {
    InboundEnvelopeValidator validator = new InboundEnvelopeValidator(SESSION, 1, 0);
    assertDoesNotThrow(() -> validator.accept(envelope(1, SESSION, 1, 0, true)));
    assertDoesNotThrow(() -> validator.accept(envelope(2, SESSION, 1, 0, false)));
  }

  @Test
  void daemonHelloAndPostHelloEnvelopesRequireMessageIds() {
    AgentEnvelope validHello =
        AgentEnvelope.newBuilder()
            .setProtocolMajor(1)
            .setRuntimeSessionId(ByteString.copyFrom(SESSION))
            .setSessionSeq(0)
            .setMessageId("daemon-hello")
            .setDaemonHello(DaemonHello.getDefaultInstance())
            .build();
    assertDoesNotThrow(() -> InboundEnvelopeValidator.validateHello(validHello, SESSION));
    assertThrows(
        ClientException.class,
        () ->
            InboundEnvelopeValidator.validateHello(
                validHello.toBuilder().clearMessageId().build(), SESSION));

    InboundEnvelopeValidator validator = new InboundEnvelopeValidator(SESSION, 1, 0);
    assertThrows(
        ClientException.class,
        () ->
            validator.accept(
                envelope(1, SESSION, 1, 0, true).toBuilder().clearMessageId().build()));
  }

  @Test
  void rejectsReplayGapWrongIdentityAndWrongVersion() throws Exception {
    InboundEnvelopeValidator replay = new InboundEnvelopeValidator(SESSION, 1, 0);
    replay.accept(envelope(1, SESSION, 1, 0, true));
    assertThrows(ClientException.class, () -> replay.accept(envelope(1, SESSION, 1, 0, false)));

    InboundEnvelopeValidator gap = new InboundEnvelopeValidator(SESSION, 1, 0);
    assertThrows(ClientException.class, () -> gap.accept(envelope(2, SESSION, 1, 0, false)));

    byte[] wrongSession = SESSION.clone();
    wrongSession[0] = 1;
    InboundEnvelopeValidator identity = new InboundEnvelopeValidator(SESSION, 1, 0);
    assertThrows(
        ClientException.class, () -> identity.accept(envelope(1, wrongSession, 1, 0, false)));

    InboundEnvelopeValidator version = new InboundEnvelopeValidator(SESSION, 1, 0);
    assertThrows(ClientException.class, () -> version.accept(envelope(1, SESSION, 1, 1, false)));

    InboundEnvelopeValidator type = new InboundEnvelopeValidator(SESSION, 1, 0);
    AgentEnvelope unsupported =
        AgentEnvelope.newBuilder()
            .setProtocolMajor(1)
            .setRuntimeSessionId(ByteString.copyFrom(SESSION))
            .setSessionSeq(1)
            .setMessageId("daemon-1")
            .build();
    assertThrows(ClientException.class, () -> type.accept(unsupported));
  }

  private static AgentEnvelope envelope(
      long sequence, byte[] session, int major, int minor, boolean health) {
    AgentEnvelope.Builder builder =
        AgentEnvelope.newBuilder()
            .setProtocolMajor(major)
            .setProtocolMinor(minor)
            .setRuntimeSessionId(ByteString.copyFrom(session))
            .setSessionSeq(sequence)
            .setMessageId("daemon-" + sequence);
    if (health) builder.setHealth(Health.getDefaultInstance());
    else builder.setAck(Ack.getDefaultInstance());
    return builder.build();
  }
}
