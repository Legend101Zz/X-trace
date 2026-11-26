package dev.xtrace.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class JerseyBridgeTest {
  enum Dispatch { REQUEST, ASYNC, FORWARD, INCLUDE, ERROR }

  public record Request(Dispatch kind, Boolean async) {
    public Dispatch getDispatcherType() {
      if (kind == null) throw new IllegalStateException("dispatcher getter failed");
      return kind;
    }

    public boolean isAsyncStarted() {
      if (async == null) throw new IllegalStateException("async getter failed");
      return async;
    }
  }

  public static class MissingAsync {
    public Dispatch getDispatcherType() {
      return Dispatch.REQUEST;
    }
  }

  private static boolean unavailableAfter(Object request) {
    SpringMvcBridge.servletEnter();
    Object activation = JerseyBridge.serviceEnter(JerseyBridgeTest.class, request);
    try {
      // An excluded activation must not bind or attempt to resolve a Jersey request.
      JerseyBridge.bindRequest(JerseyBridgeTest.class, new Object(), request);
      assertFalse(JerseyBridge.dispatchEnter(null, null));
    } finally {
      JerseyBridge.serviceExit(activation, null);
      SpringMvcBridge.servletEnd(request, null, null);
    }
    boolean unavailable = JerseyBridge.takeObservationUnavailable();
    assertFalse(JerseyBridge.takeObservationUnavailable());
    return unavailable;
  }

  @Test
  void unreadableDispatcherRaisesFixedCoverageNotice() {
    assertTrue(unavailableAfter(new Object()));
    assertTrue(unavailableAfter(new Request(null, false)));
  }

  @Test
  void unreadableAsyncStateRaisesFixedCoverageNotice() {
    assertTrue(unavailableAfter(new MissingAsync()));
    assertTrue(unavailableAfter(new Request(Dispatch.REQUEST, null)));
  }

  @Test
  void knownRedispatchKindsDoNotReportAGetterFailure() {
    for (Dispatch kind : new Dispatch[] {Dispatch.ASYNC, Dispatch.FORWARD, Dispatch.INCLUDE, Dispatch.ERROR}) {
      assertFalse(unavailableAfter(new Request(kind, null)));
    }
  }

  @Test
  void activeAsyncRequestIsDeliberatelyExcluded() {
    assertFalse(unavailableAfter(new Request(Dispatch.REQUEST, true)));
  }
}
