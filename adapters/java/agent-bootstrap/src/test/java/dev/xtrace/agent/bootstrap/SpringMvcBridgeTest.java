package dev.xtrace.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SpringMvcBridgeTest {
  private final Sink sink = new Sink();

  @BeforeEach
  void install() {
    BootstrapBridge.resetForTest();
    SpringMvcBridge.resetForTest();
    assertTrue(BootstrapBridge.install(sink));
  }

  @AfterEach
  void reset() {
    BootstrapBridge.resetForTest();
    SpringMvcBridge.resetForTest();
  }

  @Test
  void outerFilterSeesPostChainStatusAndOwnsCompletionAcrossNestedServlets() {
    Request request = new Request("GET", "/post-chain");
    Response response = new Response(200);
    SpringMvcBridge.servletEnter(); // outer filter
    SpringMvcBridge.servletEnter(); // inner filter
    SpringMvcBridge.servletEnter(); // Servlet.service
    SpringMvcBridge.dispatchEnter();
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, response, null);
    SpringMvcBridge.dispatchEnd(response, null);
    assertEquals(0, sink.finishes);
    SpringMvcBridge.servletEnd(request, response, null);
    SpringMvcBridge.servletEnd(request, response, null);
    assertEquals(0, sink.finishes, "inner service and filter must not close the root");
    response.status = 304;
    response.committed = true;
    SpringMvcBridge.servletEnd(request, response, null);
    assertEquals(BridgeSink.Outcome.RESPONDED, sink.outcome.kind());
    assertEquals(304, sink.outcome.httpStatus());
    assertEquals(304, sink.status);
    assertEquals("http.response 304", sink.symbols.get(1));
    assertEquals(1, sink.finishes);
    assertFalse(BootstrapBridge.hasContext());
  }

  @Test
  void uncommittedOuterStatusIsProvisionalEvenOnNormalReturn() {
    Request request = new Request("GET", "/buffered");
    Response response = new Response(210);
    SpringMvcBridge.servletEnter();
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, response, null);
    assertEquals(0, sink.finishes);
    SpringMvcBridge.servletEnd(request, response, null);
    assertProvisional(210);
    assertEquals(1, sink.finishes);
    assertEquals(0, sink.dropped, "an unobserved outcome is not event loss");
  }

  @Test
  void sendErrorRemainsProvisionalEvenIfContainerReportsCommitted() {
    Request request = new Request("GET", "/send-error");
    Response response = new Response(418);
    response.committed = true;
    SpringMvcBridge.servletEnter();
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.servletSendError();
    SpringMvcBridge.end(request, response, null);
    SpringMvcBridge.servletEnd(request, response, null);
    assertProvisional(418);
    Request error = new Request("GET", "/error");
    error.dispatcher = Dispatch.ERROR;
    SpringMvcBridge.servletEnter();
    assertFalse(SpringMvcBridge.start(error, new Handler(Controller.class)));
    response.status = 451;
    SpringMvcBridge.servletEnd(error, response, null);
    assertEquals(1, sink.starts());
    assertEquals(1, sink.finishes);
    assertProvisional(418);
  }

  @Test
  void nestedDispatchAndLaterIncludeStayInOneServletOwnedRecording() {
    Request request = new Request("GET", "/outer");
    Response response = new Response(200);
    SpringMvcBridge.servletEnter();
    SpringMvcBridge.dispatchEnter();
    SpringMvcBridge.dispatchEnter();
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, response, null);
    SpringMvcBridge.dispatchEnd(response, null);
    SpringMvcBridge.dispatchEnd(response, null);
    // A second dispatch tree within the same filter invocation must not replace the root.
    SpringMvcBridge.servletEnter();
    SpringMvcBridge.dispatchEnter();
    assertFalse(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.dispatchEnd(response, null);
    SpringMvcBridge.servletEnd(request, response, null);
    assertEquals(0, sink.finishes);
    String frame = BootstrapBridge.frameEnter(Controller.class, "afterNested", "()V");
    BootstrapBridge.frameExit(frame, null);
    response.status = 207;
    response.committed = true;
    SpringMvcBridge.servletEnd(request, response, null);
    assertEquals(207, sink.outcome.httpStatus());
    assertEquals(1, sink.starts());
    assertEquals(1, sink.finishes);
  }

  @Test
  void servletDepthAndErrorMarkerAreClearedOnAReusedThread() {
    SpringMvcBridge.servletEnd(null, null, null); // unmatched exit is harmless
    SpringMvcBridge.servletEnter();
    SpringMvcBridge.servletSendError();
    SpringMvcBridge.servletEnd(null, null, new IllegalStateException("no handler"));
    Request request = new Request("GET", "/next");
    Response response = new Response(204);
    response.committed = true;
    SpringMvcBridge.servletEnter();
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, response, null);
    SpringMvcBridge.servletEnd(request, response, null);
    assertEquals(204, sink.outcome.httpStatus());
    assertEquals(1, sink.finishes);
  }

  @Test
  void servletDepthDoesNotDeferAHandlerOnAnotherThread() throws Exception {
    SpringMvcBridge.servletEnter();
    java.util.concurrent.FutureTask<Boolean> isolated = new java.util.concurrent.FutureTask<>(() -> {
      boolean started = SpringMvcBridge.start(
          new Request("GET", "/other-thread"), new Handler(Controller.class));
      SpringMvcBridge.end(new Response(204), null);
      return started && !BootstrapBridge.hasContext();
    });
    Thread thread = new Thread(isolated);
    thread.start();
    thread.join();
    assertTrue(isolated.get());
    SpringMvcBridge.servletEnd(null, null, null);
    assertProvisional(204);
  }

  @Test
  void unreadableCommitStateCannotMakeAStatusFinal() {
    Request request = new Request("GET", "/unknown-commit");
    SpringMvcBridge.servletEnter();
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, new Response(200), null);
    SpringMvcBridge.servletEnd(request, new MissingCommitResponse(), null);
    assertProvisional(209);
    assertEquals(1, sink.finishes);
  }

  @Test
  void asyncRootWaitsForOuterServletExitButNeverClaimsTheEarlyStatus() {
    Request request = new Request("GET", "/async");
    Response response = new Response(200);
    response.committed = true;
    SpringMvcBridge.servletEnter();
    SpringMvcBridge.dispatchEnter();
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    request.asyncStarted = true;
    SpringMvcBridge.end(request, response, null);
    SpringMvcBridge.dispatchEnd(response, null);
    assertEquals(0, sink.finishes);
    // Even if async processing completes concurrently, its final response was not observed here.
    request.asyncStarted = false;
    SpringMvcBridge.servletEnd(request, response, null);
    assertEquals(BridgeSink.Outcome.UNOBSERVED, sink.outcome.kind());
    assertEquals(0, sink.status);
    assertEquals(1, sink.finishes);
    assertFalse(BootstrapBridge.hasContext());
  }

  @Test
  void invalidProvisionalStatusesNeverEnterTheOutcomeOrTheEvidenceLabel() {
    for (int status : new int[] {-1, 0, 600, Integer.MAX_VALUE}) {
      assertTrue(BootstrapBridge.requestStart("GET", "/invalid-status"));
      BootstrapBridge.provisionalRequestEnd(status, null);
      assertEquals(BridgeSink.Outcome.UNOBSERVED, sink.outcome.kind());
      assertEquals(0, sink.status);
      assertEquals(0, sink.outcome.httpStatus());
      assertEquals("http.response unavailable; final status not observed; provisional status unavailable",
          sink.symbols.get(sink.symbols.size() - 1));
    }
  }

  @Test
  void matchesAnyHandlerMethodAndRecordsTemplateNotPath() {
    Request request = new Request("GET", "/owners/{ownerId}");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), null);
    assertEquals("GET", sink.method);
    assertEquals("/owners/{ownerId}", sink.route);
    assertEquals("http.request GET /owners/{ownerId}", sink.symbols.get(0));
    assertEquals(provisionalLabel(200), sink.symbols.get(1));
    assertProvisional(200);
    assertFalse(BootstrapBridge.hasContext());
  }

  @Test
  void asyncStartedHandlerClosesUnobservedAndTheAsyncRedispatchOpensNoSecondRoot() {
    Request async = new Request("GET", "/slow");
    async.asyncStarted = true;
    assertTrue(SpringMvcBridge.start(async, new Handler(Controller.class)));
    SpringMvcBridge.end(async, new Response(200), null);
    assertEquals(0, sink.status);
    assertEquals("http.response unavailable", sink.symbols.get(1));
    assertEquals(BridgeSink.Outcome.UNOBSERVED, sink.outcome.kind());
    assertFalse(BootstrapBridge.hasContext());
    int before = sink.symbols.size();
    Request redispatch = new Request("GET", "/slow");
    redispatch.dispatcher = Dispatch.ASYNC;
    assertFalse(SpringMvcBridge.start(redispatch, new Handler(Controller.class)));
    assertEquals(before, sink.symbols.size());
  }

  @Test
  void syncHandlerWithoutServletBoundaryReportsProvisionalStatus() {
    Request sync = new Request("GET", "/fast");
    assertTrue(SpringMvcBridge.start(sync, new Handler(Controller.class)));
    SpringMvcBridge.end(sync, new Response(201), null);
    assertProvisional(201);
  }

  @Test
  void requestWithoutMatchedPatternIsNotRecordedAndNeverFallsBackToThePath() {
    Request request = new Request("GET", null);
    assertFalse(SpringMvcBridge.start(request, new Handler(Controller.class)));
    assertTrue(sink.symbols.isEmpty());
    assertFalse(BootstrapBridge.hasContext());
  }

  @Test
  void nonMatchedRequestIsNotRecorded() {
    assertFalse(SpringMvcBridge.start(new Request("GET", "/x"), null));
    assertFalse(SpringMvcBridge.start(null, new Handler(Controller.class)));
    assertTrue(sink.symbols.isEmpty());
  }

  @Test
  void queryOrFragmentOrSpaceInATemplateRejectsTheRecording() {
    for (String bad : new String[] {"/a?b=1", "/a#f", "/a b", "a/b", "", "/" + "x".repeat(300)}) {
      assertFalse(
          SpringMvcBridge.start(new Request("GET", bad), new Handler(Controller.class)), bad);
    }
    assertFalse(
        SpringMvcBridge.start(new Request("BREW", "/pot"), new Handler(Controller.class)));
    assertFalse(BootstrapBridge.hasContext());
  }

  @Test
  void outOfScopeHandlerIsNotRecorded() {
    sink.scope = 0;
    assertFalse(SpringMvcBridge.start(new Request("GET", "/error"), new Handler(Controller.class)));
    assertTrue(sink.symbols.isEmpty());
  }

  @Test
  void unknownScopeRecordsTheRootAndReportsHandlerUnresolved() {
    sink.scope = -1;
    assertTrue(SpringMvcBridge.start(new Request("GET", "/ping"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), null);
    assertEquals(
        List.of(
            "http.request GET /ping",
            BootstrapBridge.HANDLER_UNRESOLVED_SYMBOL,
            provisionalLabel(200)),
        sink.symbols);
    assertEquals(BridgeEventKind.GAP, sink.kinds.get(1));
  }

  @Test
  void nestedDispatchDoesNotOpenASecondRoot() {
    assertTrue(SpringMvcBridge.start(new Request("GET", "/a"), new Handler(Controller.class)));
    assertFalse(SpringMvcBridge.start(new Request("GET", "/b"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), null);
    assertEquals(1, sink.starts());
  }

  @Test
  void redirectStatusSetWhileTheViewRendersIsTheRecordedOutcome() {
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("POST", "/owners/new");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    Response response = new Response(200);
    SpringMvcBridge.end(request, response, null);
    // The handler returned with the default status; the redirect view has not run yet.
    assertTrue(BootstrapBridge.awaitingResolution());
    assertEquals(1, sink.symbols.size(), "no response event before the dispatch ends");
    response.status = 302;
    SpringMvcBridge.dispatchEnd(response, null);
    assertFalse(BootstrapBridge.hasContext());
    assertEquals(BridgeSink.Outcome.UNOBSERVED, sink.outcome.kind());
    assertProvisional(302);
    assertEquals(provisionalLabel(302), sink.symbols.get(1));
    assertEquals(1, sink.starts());
  }

  @Test
  void forwardAndIncludeDuringRenderingCannotCloseTheirOwningDispatch() {
    for (Dispatch kind : new Dispatch[] {Dispatch.FORWARD, Dispatch.INCLUDE}) {
      SpringMvcBridge.dispatchEnter();
      Request outer = new Request("GET", "/outer");
      assertTrue(SpringMvcBridge.start(outer, new Handler(Controller.class)));
      Response response = new Response(200);
      SpringMvcBridge.end(outer, response, null);
      int starts = sink.starts();
      int finishes = sink.finishes;
      // The adapter returned; the outer view now enters a nested DispatcherServlet.
      for (int i = 0; i < 2; i++) {
        SpringMvcBridge.dispatchEnter();
        Request nested = new Request("GET", "/inner");
        nested.dispatcher = kind;
        assertFalse(SpringMvcBridge.start(nested, new Handler(Controller.class)));
      }
      SpringMvcBridge.exceptionResolved(new Response(409), new Object(), null);
      SpringMvcBridge.dispatchEnd(new Response(202), null);
      SpringMvcBridge.dispatchEnd(new Response(203), new IllegalStateException("nested"));
      assertTrue(BootstrapBridge.awaitingResolution(), kind.name());
      assertEquals(finishes, sink.finishes, "nested dispatch must not emit a finish");
      // Outer rendering continues after the nested dispatch; these frames must remain captured.
      String frame = BootstrapBridge.frameEnter(Controller.class, "afterNested", "()V");
      BootstrapBridge.frameExit(frame, null);
      response.status = 207;
      SpringMvcBridge.dispatchEnd(response, null);
      assertEquals(starts, sink.starts());
      assertEquals(finishes + 1, sink.finishes);
      assertProvisional(207);
      assertTrue(sink.symbols.contains("SpringMvcBridgeTest$Controller.afterNested"));
      assertFalse(BootstrapBridge.hasContext());
    }
  }

  @Test
  void rootOpenedInANestedDispatchClosesWithThatDispatch() {
    SpringMvcBridge.dispatchEnter();
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("GET", "/nested-first-handler");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, new Response(200), null);
    SpringMvcBridge.dispatchEnd(new Response(201), null);
    assertEquals(1, sink.finishes);
    assertFalse(BootstrapBridge.hasContext());
    // A second include in the same outer dispatch tree is still the same HTTP request.
    SpringMvcBridge.dispatchEnter();
    assertFalse(SpringMvcBridge.start(
        new Request("GET", "/second-include"), new Handler(Controller.class)));
    SpringMvcBridge.dispatchEnd(new Response(202), null);
    SpringMvcBridge.dispatchEnd(new Response(500), null);
    assertEquals(1, sink.starts());
    assertEquals(1, sink.finishes);
    assertProvisional(201);
  }

  @Test
  void dispatchStateIsRemovedEvenWhenNoHandlerWasRecorded() {
    SpringMvcBridge.dispatchEnter();
    SpringMvcBridge.dispatchEnd(new Response(200), null);
    assertTrue(SpringMvcBridge.start(new Request("GET", "/outside"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(204), null);
    assertFalse(BootstrapBridge.hasContext());
    assertProvisional(204);
  }

  @Test
  void anotherThreadsLiveDispatchDoesNotDeferThisThreadsHandler() throws Exception {
    SpringMvcBridge.dispatchEnter();
    java.util.concurrent.FutureTask<Boolean> isolated = new java.util.concurrent.FutureTask<>(() -> {
      boolean started = SpringMvcBridge.start(
          new Request("GET", "/other-thread"), new Handler(Controller.class));
      SpringMvcBridge.end(new Response(204), null);
      return started && !BootstrapBridge.hasContext();
    });
    Thread thread = new Thread(isolated);
    thread.start();
    thread.join();
    assertTrue(isolated.get());
    SpringMvcBridge.dispatchEnd(new Response(200), null);
  }

  @Test
  void asyncWithLiveDispatchHookClosesOnceUnobservedAndLeavesNoDeferredState() {
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("GET", "/async");
    request.asyncStarted = true;
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, new Response(200), null);
    assertEquals(BridgeSink.Outcome.UNOBSERVED, sink.outcome.kind());
    assertFalse(BootstrapBridge.hasContext());
    SpringMvcBridge.dispatchEnd(new Response(200), null);
    SpringMvcBridge.dispatchEnter();
    Request redispatch = new Request("GET", "/async");
    redispatch.dispatcher = Dispatch.ASYNC;
    assertFalse(SpringMvcBridge.start(redispatch, new Handler(Controller.class)));
    SpringMvcBridge.dispatchEnd(new Response(206), null);
    assertEquals(1, sink.starts());
    assertEquals(1, sink.finishes);
    assertTrue(SpringMvcBridge.start(new Request("GET", "/next"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(204), null);
    assertEquals(2, sink.finishes);
    assertFalse(BootstrapBridge.hasContext());
  }

  @Test
  void normalReturnClearsHandledThrowBeforeAnUnrelatedRenderingFailure() {
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("GET", "/handled");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    String frame = BootstrapBridge.frameEnter(Controller.class, "caught", "()V");
    BootstrapBridge.frameExit(frame, new IllegalArgumentException("handled"));
    SpringMvcBridge.end(request, new Response(200), null);
    SpringMvcBridge.dispatchEnd(new Response(200), new IllegalStateException("render"));
    assertEquals(BridgeSink.Outcome.EXCEPTION_PROPAGATED, sink.outcome.kind());
    assertEquals("java.lang.IllegalStateException", sink.outcome.exceptionType());
    assertEquals(null, sink.outcome.thrownFromEventId());
  }

  @Test
  void rejectedThrowEventCannotReuseAnEarlierHandledThrowsIdentity() {
    assertTrue(BootstrapBridge.requestStart("GET", "/throw-loss"));
    String frame = BootstrapBridge.frameEnter(Controller.class, "caught", "()V");
    BootstrapBridge.frameExit(frame, new IllegalArgumentException("handled"));
    sink.rejectThrow = true;
    IllegalStateException failure = new IllegalStateException("propagated");
    frame = BootstrapBridge.frameEnter(Controller.class, "failing", "()V");
    BootstrapBridge.frameExit(frame, failure);
    BootstrapBridge.deferRequestEnd(failure);
    BootstrapBridge.requestEnd(0, failure);
    assertEquals(BridgeSink.Outcome.EXCEPTION_PROPAGATED, sink.outcome.kind());
    assertEquals("java.lang.IllegalStateException", sink.outcome.exceptionType());
    assertEquals(null, sink.outcome.thrownFromEventId());
    assertEquals(1, sink.dropped, "only the rejected event is lost");
  }

  @Test
  void staleNormalDeferralNeverPropagatesAHandledThrow() {
    assertTrue(BootstrapBridge.requestStart("GET", "/first"));
    String frame = BootstrapBridge.frameEnter(Controller.class, "caught", "()V");
    BootstrapBridge.frameExit(frame, new IllegalArgumentException("handled"));
    assertTrue(BootstrapBridge.deferRequestEnd(null));
    assertTrue(BootstrapBridge.requestStart("GET", "/next"));
    assertEquals(BridgeSink.Outcome.UNOBSERVED, sink.outcome.kind());
    assertEquals(null, sink.outcome.exceptionType());
    assertEquals(null, sink.outcome.thrownFromEventId());
    BootstrapBridge.requestEnd(204, (Throwable) null);
  }

  @Test
  void staleThrowDeferralUsesOnlyTheThrowThatCausedDeferral() {
    assertTrue(BootstrapBridge.requestStart("GET", "/first"));
    assertTrue(BootstrapBridge.deferRequestEnd(new IllegalStateException("unresolved")));
    String frame = BootstrapBridge.frameEnter(Controller.class, "caughtInView", "()V");
    BootstrapBridge.frameExit(frame, new IllegalArgumentException("handled by view"));
    assertTrue(BootstrapBridge.requestStart("GET", "/next"));
    assertEquals("java.lang.IllegalStateException", sink.outcome.exceptionType());
    assertEquals(null, sink.outcome.thrownFromEventId());
    BootstrapBridge.requestEnd(204, (Throwable) null);
  }

  @Test
  void readableCommittedStatusSurvivesAnExceptionWithoutInventingEventLoss() {
    for (int status : new int[] {200, 302, 503}) {
      SpringMvcBridge.servletEnter();
      SpringMvcBridge.dispatchEnter();
      Request request = new Request("GET", "/committed");
      assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
      Response response = new Response(status);
      response.committed = true;
      SpringMvcBridge.end(request, response, null);
      SpringMvcBridge.dispatchEnd(response, new IllegalStateException("after commit"));
      SpringMvcBridge.servletEnd(request, response, new IllegalStateException("after commit"));
      assertEquals(BridgeSink.Outcome.RESPONDED, sink.outcome.kind());
      assertEquals(status, sink.outcome.httpStatus());
      assertEquals(0, sink.dropped);
      assertFalse(BootstrapBridge.hasContext());
    }
  }

  @Test
  void handlerThrowAfterCommitKeepsItsReadableStatusAtServletExit() {
    SpringMvcBridge.servletEnter();
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("GET", "/handler-committed");
    Response response = new Response(201);
    response.committed = true;
    IllegalStateException failure = new IllegalStateException("after commit");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, response, failure);
    SpringMvcBridge.exceptionResolved(response, null, failure);
    assertTrue(BootstrapBridge.awaitingResolution());
    SpringMvcBridge.dispatchEnd(response, failure);
    SpringMvcBridge.servletEnd(request, response, failure);
    assertEquals(BridgeSink.Outcome.RESPONDED, sink.outcome.kind());
    assertEquals(201, sink.status);
    assertEquals(0, sink.dropped);
  }

  @Test
  void uncommittedErrorStatusIsNotClaimedWhenTheOuterServletThrows() {
    SpringMvcBridge.servletEnter();
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("GET", "/before-commit");
    Response response = new Response(503);
    IllegalStateException failure = new IllegalStateException("before commit");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    String frame = BootstrapBridge.frameEnter(Controller.class, "failing", "()V");
    BootstrapBridge.frameExit(frame, failure);
    SpringMvcBridge.end(request, response, failure);
    SpringMvcBridge.dispatchEnd(response, failure);
    assertTrue(BootstrapBridge.hasContext());
    SpringMvcBridge.servletEnd(request, response, failure);
    assertEquals(BridgeSink.Outcome.EXCEPTION_PROPAGATED, sink.outcome.kind());
    assertEquals(0, sink.status);
    assertTrue(sink.symbols.contains(provisionalLabel(503)));
    assertTrue(sink.outcome.thrownFromEventId() != null, "same observed throwable retains its link");
    assertFalse(BootstrapBridge.hasContext());
  }

  @Test
  void unavailableCommittedStatusIsNeverGuessed() {
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("GET", "/unreadable");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, new Response(200), null);
    SpringMvcBridge.dispatchEnd(new UnreadableResponse(), new IllegalStateException("after commit"));
    assertEquals(0, sink.outcome.httpStatus());
    assertEquals(BridgeSink.Outcome.EXCEPTION_PROPAGATED, sink.outcome.kind());
  }

  @Test
  void resolverFailureWaitsForOwningDispatchAndReadsCommittedStatusThere() {
    SpringMvcBridge.servletEnter();
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("GET", "/resolver-failure");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    IllegalStateException failure = new IllegalStateException("resolver failed");
    Response response = new Response(200);
    SpringMvcBridge.end(request, response, failure);
    SpringMvcBridge.exceptionResolved(response, null, failure);
    assertTrue(BootstrapBridge.awaitingResolution());
    response.status = 409;
    response.committed = true;
    SpringMvcBridge.dispatchEnd(response, failure);
    SpringMvcBridge.servletEnd(request, response, failure);
    assertEquals(409, sink.outcome.httpStatus());
    assertEquals(0, sink.dropped);
  }

  @Test
  void containerErrorRedispatchDoesNotCreateAnotherRecording() {
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("GET", "/send-error");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, new Response(418), null);
    SpringMvcBridge.dispatchEnd(new Response(418), null);
    SpringMvcBridge.dispatchEnter();
    Request error = new Request("GET", "/error");
    error.dispatcher = Dispatch.ERROR;
    assertFalse(SpringMvcBridge.start(error, new Handler(Controller.class)));
    SpringMvcBridge.dispatchEnd(new Response(500), null);
    assertEquals(1, sink.starts());
    assertEquals(1, sink.finishes);
    assertProvisional(418);
  }

  @Test
  void withoutServletBoundaryDispatcherStatusIsExplicitlyProvisional() {
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("GET", "/post-chain-filter");
    Response response = new Response(200);
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, response, null);
    SpringMvcBridge.dispatchEnd(response, null);
    response.status = 304;
    assertProvisional(200);
    assertEquals(1, sink.finishes);
  }

  @Test
  void withoutTheDispatchHookTheRootStillClosesWhenTheHandlerReturns() {
    Request request = new Request("GET", "/owners");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, new Response(200), null);
    assertFalse(BootstrapBridge.hasContext());
    assertProvisional(200);
  }

  @Test
  void dispatchThatThrowsAfterTheHandlerReturnedPropagatesTheExceptionWithoutAStatus() {
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("GET", "/owners/{ownerId}");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    SpringMvcBridge.end(request, new Response(200), null);
    SpringMvcBridge.dispatchEnd(new Response(200), new IllegalStateException("render failed"));
    assertFalse(BootstrapBridge.hasContext());
    assertEquals(BridgeSink.Outcome.EXCEPTION_PROPAGATED, sink.outcome.kind());
    assertEquals(0, sink.status);
  }

  @Test
  void mappedExceptionWaitsForTheErrorViewStatusWhenTheDispatchHookIsLive() {
    SpringMvcBridge.dispatchEnter();
    Request request = new Request("GET", "/owners/{ownerId}");
    assertTrue(SpringMvcBridge.start(request, new Handler(Controller.class)));
    IllegalArgumentException failure = new IllegalArgumentException("no owner");
    SpringMvcBridge.end(request, new Response(200), failure);
    Response response = new Response(200);
    SpringMvcBridge.exceptionResolved(response, new Object(), null);
    assertTrue(BootstrapBridge.awaitingResolution(), "the error view has not rendered yet");
    response.status = 404;
    SpringMvcBridge.dispatchEnd(response, null);
    assertFalse(BootstrapBridge.hasContext());
    assertProvisional(404);
  }

  @Test
  void dispatchEndWithoutAnOpenRootIsIgnored() {
    SpringMvcBridge.dispatchEnd(new Response(200), null);
    assertTrue(sink.symbols.isEmpty());
  }

  @Test
  void handlerStatusWithoutServletBoundaryIsProvisional() {
    assertTrue(SpringMvcBridge.start(new Request("GET", "/owners"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), null);
    assertEquals(BridgeSink.Outcome.UNOBSERVED, sink.outcome.kind());
    assertProvisional(200);
  }

  @Test
  void exceptionPropagated500() {
    assertTrue(SpringMvcBridge.start(new Request("POST", "/orders"), new Handler(Controller.class)));
    IllegalStateException failure = new IllegalStateException("handler failed");
    SpringMvcBridge.end(new Response(200), failure);
    // The handler threw: the request stays open and the container's default status is not used.
    assertTrue(BootstrapBridge.awaitingResolution());
    assertTrue(sink.symbols.size() == 1, "no response event before resolution");
    SpringMvcBridge.exceptionResolved(new Response(200), null, failure);
    assertFalse(BootstrapBridge.hasContext());
    assertEquals(BridgeSink.Outcome.EXCEPTION_PROPAGATED, sink.outcome.kind());
    assertEquals(0, sink.outcome.httpStatus());
    assertEquals("java.lang.IllegalStateException", sink.outcome.exceptionType());
    assertEquals(null, sink.outcome.exceptionMessage());
    assertEquals(provisionalLabel(200), sink.symbols.get(1));
  }

  @Test
  void mappedExceptionWithoutServletBoundaryIsProvisional() {
    assertTrue(SpringMvcBridge.start(new Request("GET", "/owners/{id}"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), new IllegalArgumentException("no owner"));
    SpringMvcBridge.exceptionResolved(new Response(404), new Object(), null);
    assertEquals(BridgeSink.Outcome.UNOBSERVED, sink.outcome.kind());
    assertProvisional(404);
    assertEquals(null, sink.outcome.exceptionType());
  }

  @Test
  void unresolvedStatusAfterAMappedExceptionIsUnobservedNotInvented() {
    assertTrue(SpringMvcBridge.start(new Request("GET", "/x"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), new IllegalArgumentException("x"));
    SpringMvcBridge.exceptionResolved(null, new Object(), null);
    assertEquals(BridgeSink.Outcome.UNOBSERVED, sink.outcome.kind());
    assertEquals(0, sink.outcome.httpStatus());
  }

  @Test
  void resolutionWithoutADeferredRequestIsIgnored() {
    SpringMvcBridge.exceptionResolved(new Response(500), new Object(), null);
    assertTrue(sink.symbols.isEmpty());
    assertTrue(SpringMvcBridge.start(new Request("GET", "/ok"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), null);
    SpringMvcBridge.exceptionResolved(new Response(500), new Object(), null);
    assertProvisional(200);
  }

  @Test
  void staleDeferredRequestIsClosedUnobservedWhenTheNextRequestStarts() {
    assertTrue(SpringMvcBridge.start(new Request("GET", "/a"), new Handler(Controller.class)));
    SpringMvcBridge.end(new Response(200), new IllegalStateException("never resolved"));
    assertTrue(BootstrapBridge.awaitingResolution());
    assertTrue(SpringMvcBridge.start(new Request("GET", "/b"), new Handler(Controller.class)));
    assertEquals(2, sink.starts());
    assertFalse(BootstrapBridge.awaitingResolution());
    SpringMvcBridge.end(new Response(204), null);
    assertProvisional(204);
  }

  @Test
  void throwEventCarriesExceptionTypeAndWithholdsMessage() {
    assertTrue(BootstrapBridge.requestStart("GET", "/x"));
    assertEquals("SpringMvcBridgeTest$Controller.go", BootstrapBridge.frameEnter(Controller.class, "go", "()V"));
    BootstrapBridge.frameExit("SpringMvcBridgeTest$Controller.go", new IllegalStateException("m".repeat(5000)));
    assertEquals("java.lang.IllegalStateException", sink.thrownType);
    assertEquals(null, sink.thrownMessage);
    BootstrapBridge.requestEnd(500, false);
    assertEquals(BridgeSink.Outcome.RESPONDED, sink.outcome.kind());
  }

  @Test
  void throwingGetMessageNeverEscapes() {
    assertTrue(BootstrapBridge.requestStart("GET", "/x"));
    BootstrapBridge.frameEnter(Controller.class, "go", "()V");
    RuntimeException failure = new RuntimeException() {
      @Override
      public String getMessage() {
        throw new IllegalStateException("hostile getMessage");
      }
    };
    BootstrapBridge.frameExit("SpringMvcBridgeTest$Controller.go", failure);
    assertEquals(null, sink.thrownMessage);
    BootstrapBridge.requestEnd(0, failure);
    assertEquals(BridgeSink.Outcome.EXCEPTION_PROPAGATED, sink.outcome.kind());
    assertTrue(sink.outcome.thrownFromEventId() != null);
  }

  @Test
  void reflectionFailureIsContained() {
    Object hostile = new Object();
    assertFalse(SpringMvcBridge.start(hostile, new Handler(Controller.class)));
    assertEquals(0, SpringMvcBridge.status(hostile));
  }

  @Test
  void concurrentRequestsKeepOwnRoot() throws Exception {
    List<Thread> threads = new ArrayList<>();
    List<String> failures = java.util.Collections.synchronizedList(new ArrayList<>());
    for (int i = 0; i < 8; i++) {
      String route = "/r" + i;
      Thread thread =
          new Thread(
              () -> {
                for (int n = 0; n < 50; n++) {
                  if (!SpringMvcBridge.start(
                      new Request("GET", route), new Handler(Controller.class))) {
                    failures.add("start " + route);
                    return;
                  }
                  SpringMvcBridge.end(new Response(200), null);
                }
              });
      threads.add(thread);
      thread.start();
    }
    for (Thread thread : threads) thread.join();
    assertTrue(failures.isEmpty(), failures.toString());
    assertEquals(8 * 50, sink.routesByMethod("GET").size());
    Map<String, Integer> perRoute = new HashMap<>();
    for (String route : sink.routesByMethod("GET")) perRoute.merge(route, 1, Integer::sum);
    assertEquals(8, perRoute.size());
    perRoute.values().forEach(count -> assertEquals(50, count));
  }

  public static final class Controller {}

  public static final class Handler {
    private final Class<?> beanType;

    Handler(Class<?> beanType) {
      this.beanType = beanType;
    }

    public Class<?> getBeanType() {
      return beanType;
    }
  }

  public enum Dispatch { REQUEST, FORWARD, INCLUDE, ASYNC, ERROR }

  public static final class Request {
    boolean asyncStarted;
    Dispatch dispatcher = Dispatch.REQUEST;
    public boolean isAsyncStarted() {
      return asyncStarted;
    }

    public Dispatch getDispatcherType() {
      return dispatcher;
    }

    private final String method;
    private final String pattern;

    Request(String method, String pattern) {
      this.method = method;
      this.pattern = pattern;
    }

    public String getMethod() {
      return method;
    }

    public Object getAttribute(String name) {
      return SpringMvcBridge.BEST_MATCHING_PATTERN.equals(name) ? pattern : null;
    }
  }

  private static String provisionalLabel(int status) {
    return "http.response unavailable; final status not observed; observed status was "
        + status + " (provisional)";
  }

  private void assertProvisional(int status) {
    assertEquals(0, sink.status);
    assertEquals(0, sink.outcome.httpStatus());
    assertEquals(BridgeSink.Outcome.UNOBSERVED, sink.outcome.kind());
    assertTrue(sink.symbols.contains(provisionalLabel(status)), sink.symbols.toString());
  }

  public static final class MissingCommitResponse {
    public int getStatus() {
      return 209;
    }
  }

  public static final class UnreadableResponse {
    public int getStatus() {
      throw new IllegalStateException("unreadable");
    }

    public boolean isCommitted() {
      return true;
    }
  }

  public static final class Response {
    int status;
    boolean committed;

    public boolean isCommitted() {
      return committed;
    }

    Response(int status) {
      this.status = status;
    }

    public int getStatus() {
      return status;
    }
  }

  private static final class Sink implements BridgeSink {
    private final List<String> symbols = java.util.Collections.synchronizedList(new ArrayList<>());
    private final List<Integer> kinds = java.util.Collections.synchronizedList(new ArrayList<>());
    private final List<String[]> starts = new ArrayList<>();
    private volatile String method;
    private volatile String route;
    private volatile int status = -1;
    private volatile int finishes;
    private volatile long dropped;
    private volatile int scope = 1;
    private volatile BridgeSink.Outcome outcome;
    private volatile boolean rejectThrow;
    private volatile String thrownType;
    private volatile String thrownMessage;

    int starts() {
      return starts.size();
    }

    List<String> routesByMethod(String wanted) {
      List<String> result = new ArrayList<>();
      synchronized (starts) {
        for (String[] start : starts) if (start[0].equals(wanted)) result.add(start[1]);
      }
      return result;
    }

    @Override
    public boolean offerStart(String id, long ns, String method, String route) {
      this.method = method;
      this.route = route;
      synchronized (starts) {
        starts.add(new String[] {method, route});
      }
      return true;
    }

    @Override
    public boolean offerEvent(
        String id, String event, String parent, int kind, String symbol, long ns, int detail) {
      symbols.add(symbol);
      kinds.add(kind);
      return true;
    }

    @Override
    public boolean offerThrowEvent(
        String id, String event, String parent, String symbol, long ns, String type, String text) {
      if (rejectThrow) return false;
      thrownType = type;
      thrownMessage = text;
      symbols.add(symbol);
      kinds.add(BridgeEventKind.FRAME_THROW);
      return true;
    }

    @Override
    public boolean offerFinishWithOutcome(
        String id, long started, long finished, int status, long dropped, Outcome outcome) {
      this.outcome = outcome;
      return offerFinish(id, started, finished, status, dropped);
    }

    @Override
    public int applicationScope(Class<?> type) {
      return scope;
    }

    @Override
    public boolean offerFinish(String id, long started, long finished, int status, long dropped) {
      this.status = status;
      this.dropped = dropped;
      finishes++;
      return true;
    }

    @Override
    public void reportIncomplete(int failureKind) {}
  }
}
