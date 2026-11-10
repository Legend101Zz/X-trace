package dev.xtrace.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ConstructorBridgeTest {
  private final Sink sink = new Sink();

  @BeforeEach
  void install() {
    BootstrapBridge.resetForTest();
    assertTrue(BootstrapBridge.install(sink));
  }

  @AfterEach
  void reset() { BootstrapBridge.resetForTest(); }

  @Test
  void entryAndExitPreserveConstructorIdentityAndWithholdExceptionMessages() {
    assertNull(BootstrapBridge.constructorEnter(ConstructorBridgeTest.class, "()V"));
    assertTrue(BootstrapBridge.requestStart("GET", "/construct"));
    String symbol = BootstrapBridge.constructorEnter(ConstructorBridgeTest.class, "()V");
    assertEquals("ConstructorBridgeTest.<init>", symbol);
    assertEquals("<init>", sink.method);
    assertEquals("()V", sink.descriptor);
    BootstrapBridge.constructorExit(symbol, new IllegalArgumentException("private constructor input"));
    assertEquals("java.lang.IllegalArgumentException", sink.thrownType);
    assertNull(sink.thrownMessage);
    String after = BootstrapBridge.frameEnter(ConstructorBridgeTest.class, "after", "()V");
    assertEquals(sink.parents.get(0), sink.parents.get(2), "throwing constructor leaves the caller's parent active");
    BootstrapBridge.frameExit(after, (Throwable) null);
    BootstrapBridge.requestEnd(200, false);
  }

  @Test
  void callbackErrorsNeverEscapeConstructorEntryOrExit() {
    assertTrue(BootstrapBridge.requestStart("GET", "/callbacks"));
    sink.failEntry = true;
    assertNull(assertDoesNotThrow(() -> BootstrapBridge.constructorEnter(ConstructorBridgeTest.class, "()V")));
    assertDoesNotThrow(() -> BootstrapBridge.constructorExit(null, null));
    sink.failEntry = false;
    String symbol = BootstrapBridge.constructorEnter(ConstructorBridgeTest.class, "()V");
    assertNotNull(symbol);
    sink.failExit = true;
    assertDoesNotThrow(() -> BootstrapBridge.constructorExit(symbol, new IllegalStateException("original")));
    sink.failExit = false;
    String after = BootstrapBridge.constructorEnter(ConstructorBridgeTest.class, "()V");
    assertNotNull(after);
    assertEquals(sink.parents.get(0), sink.parents.get(1), "failed exit still removes its constructor frame");
    BootstrapBridge.constructorExit(after, null);
    BootstrapBridge.requestEnd(200, false);
  }

  private static final class Sink implements BridgeSink {
    final List<String> parents = new ArrayList<>();
    String method;
    String descriptor;
    String thrownType;
    String thrownMessage;
    boolean failEntry;
    boolean failExit;

    @Override
    public boolean offerStart(String recording, long time, String verb, String route) { return true; }

    @Override
    public boolean offerFrameEvent(String recording, String id, String parent, int kind, String symbol,
        long time, int detail, Class<?> type, String method, String descriptor) {
      if (failEntry) throw new AssertionError("capture entry failure");
      this.method = method;
      this.descriptor = descriptor;
      parents.add(parent);
      return true;
    }

    @Override
    public boolean offerThrowEvent(String recording, String id, String parent, String symbol,
        long time, String type, String message) {
      if (failExit) throw new AssertionError("capture exit failure");
      thrownType = type;
      thrownMessage = message;
      parents.add(parent);
      return true;
    }

    @Override
    public boolean offerEvent(String recording, String id, String parent, int kind,
        String symbol, long time, int detail) { return true; }

    @Override
    public boolean offerFinish(String recording, long started, long finished, int status, long dropped) {
      return true;
    }

    @Override
    public void reportIncomplete(int kind) {}
  }
}
