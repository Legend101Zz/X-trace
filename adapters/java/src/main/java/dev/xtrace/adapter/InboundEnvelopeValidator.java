package dev.xtrace.adapter;

import com.google.protobuf.ByteString;
import xtp.agent.v1.Envelope.AgentEnvelope;

/** Connection-local validator for the daemon's independently sequenced post-hello stream. */
final class InboundEnvelopeValidator {
  private final ByteString runtimeSessionId;
  private final int protocolMajor;
  private final int protocolMinor;
  private long nextSequence = 1;

  InboundEnvelopeValidator(byte[] runtimeSessionId, int protocolMajor, int protocolMinor) {
    this.runtimeSessionId = ByteString.copyFrom(runtimeSessionId);
    this.protocolMajor = protocolMajor;
    this.protocolMinor = protocolMinor;
  }

  static void validateHello(AgentEnvelope envelope, byte[] runtimeSessionId)
      throws ClientException {
    if (envelope.getPayloadCase() != AgentEnvelope.PayloadCase.DAEMON_HELLO
        || envelope.getSessionSeq() != 0
        || envelope.getMessageId().isEmpty()
        || !envelope.getRuntimeSessionId().equals(ByteString.copyFrom(runtimeSessionId))) {
      throw new ClientException("XTR-JAVA-HANDSHAKE", "daemon hello identity is invalid");
    }
  }

  void accept(AgentEnvelope envelope) throws ClientException {
    AgentEnvelope.PayloadCase payload = envelope.getPayloadCase();
    if (!envelope.getRuntimeSessionId().equals(runtimeSessionId)
        || envelope.getProtocolMajor() != protocolMajor
        || envelope.getProtocolMinor() != protocolMinor
        || (payload != AgentEnvelope.PayloadCase.HEALTH && payload != AgentEnvelope.PayloadCase.ACK)
        || envelope.getMessageId().isEmpty()
        || envelope.getSessionSeq() != nextSequence) {
      throw new ClientException(
          "XTR-JAVA-TRANSPORT", "daemon envelope identity or sequence is invalid");
    }
    if (nextSequence == Long.MAX_VALUE) {
      throw new ClientException("XTR-JAVA-SEQUENCE", "daemon session sequence is exhausted");
    }
    nextSequence++;
  }
}
