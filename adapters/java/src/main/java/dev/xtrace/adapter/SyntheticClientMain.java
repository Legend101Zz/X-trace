package dev.xtrace.adapter;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.google.protobuf.ByteString;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.UUID;
import org.bouncycastle.crypto.digests.Blake3Digest;
import xtp.agent.v1.CapabilityOuterClass.CapabilitySet;
import xtp.agent.v1.Recording.EventBatch;
import xtp.agent.v1.Recording.RecordingEvent;
import xtp.agent.v1.Recording.RecordingEventKind;
import xtp.agent.v1.Recording.RecordingFinished;
import xtp.agent.v1.Recording.RecordingStarted;
import xtp.agent.v1.Transport.Ack;

/** Private conformance executable that stages one synthetic XTP recording. */
public final class SyntheticClientMain {
  private static final JsonFactory JSON = JsonFactory.builder().build();

  private SyntheticClientMain() {}

  /** Runs the bounded synthetic conformance client. */
  public static void main(String[] args) {
    int result = run(args);
    if (result != 0) System.exit(result);
  }

  static int run(String[] args) {
    try {
      if (args.length != 2 || !args[0].equals("--bootstrap")) {
        throw new ClientException(
            "XTR-JAVA-ARGUMENT", "usage: xtrace-java-synthetic --bootstrap <bootstrap-path>");
      }
      stageSynthetic(Path.of(args[1]));
      return 0;
    } catch (ClientException error) {
      writeError(error);
      return 1;
    } catch (RuntimeException error) {
      writeError(new ClientException("XTR-JAVA-CLIENT", "synthetic XTP client failed", error));
      return 1;
    }
  }

  private static void stageSynthetic(Path bootstrapPath) throws ClientException {
    byte[] manifest = resource("/synthetic-manifest.json", 64 * 1024);
    try (Bootstrap bootstrap = BootstrapReader.read(bootstrapPath);
        XtpSession session =
            XtpSession.open(
                bootstrap,
                manifest,
                new XtpSession.ClientIdentity(
                    "xtrace-java-synthetic-client",
                    "0.0.1",
                    "java",
                    "openjdk",
                    System.getProperty("java.version"),
                    ProcessHandle.current().pid(),
                    System.nanoTime()))) {
      UUID recordingId = UUID.randomUUID();
      byte[] recordingBytes = Identifiers.uuidBytes(recordingId);
      String eventId = recordingId + ":event-1";
      RecordingEvent event =
          RecordingEvent.newBuilder()
              .setEventId(eventId)
              .setRecordingSeq(2)
              .setMonotonicNs(System.nanoTime())
              .setPriority(1)
              .setKind(RecordingEventKind.RECORDING_EVENT_KIND_FRAME_ENTER)
              .setSymbol("synthetic.handler")
              .build();
      int acknowledgements = 0;
      session.send("java-synthetic-capabilities", "", CapabilitySet.newBuilder().build());
      acknowledgements++;
      Ack started =
          session.send(
              "java-synthetic-recording-started",
              recordingId.toString(),
              RecordingStarted.newBuilder()
                  .setRecordingId(ByteString.copyFrom(recordingBytes))
                  .setRecordingSeq(1)
                  .setMethod("GET")
                  .setMatchedRouteTemplate("/__xtrace_synthetic")
                  .setUrlShape("/__xtrace_synthetic")
                  .setStartMonotonicNs(System.nanoTime())
                  .build());
      requireRecordingAck(started, recordingId, 1);
      acknowledgements++;
      Ack eventAck =
          session.send(
              "java-synthetic-event-batch",
              recordingId.toString(),
              EventBatch.newBuilder()
                  .setRecordingId(ByteString.copyFrom(recordingBytes))
                  .addEvents(event)
                  .build());
      requireRecordingAck(eventAck, recordingId, 2);
      acknowledgements++;
      byte[] digest = blake3(eventId.getBytes(StandardCharsets.UTF_8));
      Ack finished =
          session.send(
              "java-synthetic-recording-finished",
              recordingId.toString(),
              RecordingFinished.newBuilder()
                  .setRecordingId(ByteString.copyFrom(recordingBytes))
                  .setFinalRecordingSeq(2)
                  .setDurationNs(1)
                  .setEventDigest(ByteString.copyFrom(digest))
                  .build());
      requireRecordingAck(finished, recordingId, 2);
      acknowledgements++;
      writeReceipt(recordingId.toString(), eventId, acknowledgements);
    } finally {
      java.util.Arrays.fill(manifest, (byte) 0);
    }
  }

  private static void requireRecordingAck(Ack ack, UUID recordingId, long expected)
      throws ClientException {
    if (ack.getHighestContiguousRecordingSeqOrDefault(recordingId.toString(), 0) != expected) {
      throw new ClientException("XTR-JAVA-ACK", "recording acknowledgement is invalid");
    }
  }

  private static byte[] resource(String name, int maximum) throws ClientException {
    try (InputStream input = SyntheticClientMain.class.getResourceAsStream(name)) {
      if (input == null)
        throw new ClientException("XTR-JAVA-MANIFEST", "synthetic manifest is missing");
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      byte[] buffer = new byte[4096];
      int total = 0;
      int count;
      while ((count = input.read(buffer)) >= 0) {
        total += count;
        if (total > maximum)
          throw new ClientException("XTR-JAVA-MANIFEST", "synthetic manifest is too large");
        output.write(buffer, 0, count);
      }
      return output.toByteArray();
    } catch (IOException error) {
      throw new ClientException("XTR-JAVA-MANIFEST", "synthetic manifest could not be read", error);
    }
  }

  private static byte[] blake3(byte[] bytes) {
    Blake3Digest digest = new Blake3Digest(256);
    digest.update(bytes, 0, bytes.length);
    byte[] output = new byte[32];
    digest.doFinal(output, 0);
    return output;
  }

  private static void writeReceipt(String recordingId, String eventId, int acknowledgements)
      throws ClientException {
    try (JsonGenerator generator = JSON.createGenerator(System.out)) {
      generator.writeStartObject();
      generator.writeStringField("kind", "synthetic_recording_staged");
      generator.writeStringField("recording_id", recordingId);
      generator.writeStringField("event_id", eventId);
      generator.writeNumberField("staged_acks", acknowledgements);
      generator.writeBooleanField("capture_supported", false);
      generator.writeEndObject();
      generator.writeRaw('\n');
    } catch (IOException error) {
      throw new ClientException("XTR-JAVA-OUTPUT", "synthetic receipt could not be written", error);
    }
  }

  private static void writeError(ClientException error) {
    try (JsonGenerator generator = JSON.createGenerator(System.err)) {
      generator.writeStartObject();
      generator.writeStringField("code", error.code());
      generator.writeStringField("message", error.getMessage());
      generator.writeEndObject();
      generator.writeRaw('\n');
    } catch (IOException ignored) {
      // The diagnostic stream itself is unavailable; no credential-bearing fallback is emitted.
    }
  }
}
