package dev.xtrace.agent.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.bootstrap.BridgeEventKind;
import dev.xtrace.agent.bootstrap.BridgeSink;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.pool.TypePool;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Applies the real frame advice and matcher to sample classes loaded in an isolated loader. */
class FrameInstrumentationTest {
  private static final String PKG = "dev.xtrace.agent.runtime.testapp.";
  private final CapturingSink sink = new CapturingSink();
  private Object controller;

  @BeforeEach
  void install() throws Exception {
    assertTrue(BootstrapBridge.install(sink));
    ClassLoader parent = getClass().getClassLoader();
    Map<String, byte[]> definitions = new HashMap<>();
    for (String name : List.of("SampleController", "SampleService", "SampleRepository")) {
      TypeDescription type = TypePool.Default.of(parent).describe(PKG + name).resolve();
      definitions.put(
          PKG + name,
          new ByteBuddy()
              .redefine(type, ClassFileLocator.ForClassLoader.of(parent))
              .visit(
                  Advice.to(FixtureInstrumentation.FrameAdvice.class)
                      .on(FixtureInstrumentation.frameMethods()))
              .make()
              .getBytes());
    }
    controller =
        new Isolated(parent, definitions)
            .loadClass(PKG + "SampleController")
            .getDeclaredConstructor()
            .newInstance();
  }

  @AfterEach
  void reset() {
    BootstrapBridge.disable(sink);
    if (BootstrapBridge.hasContext()) BootstrapBridge.requestEnd(0, true);
  }

  private Object call(Object target, String method, String argument) throws Exception {
    try {
      return target.getClass().getMethod(method, String.class).invoke(target, argument);
    } catch (InvocationTargetException failure) {
      if (failure.getCause() instanceof Exception cause) throw cause;
      throw failure;
    }
  }

  private List<String> symbols() {
    List<String> result = new ArrayList<>();
    for (Frame frame : sink.frames) result.add(frame.kind + ":" + frame.symbol);
    return result;
  }

  @Test
  void controllerServiceRepositoryFramesNestInOrder() throws Exception {
    assertTrue(BootstrapBridge.requestStart("POST", "/orders"));
    assertEquals("ABC", call(controller, "create", "abc"));
    BootstrapBridge.requestEnd(201, false);
    assertEquals(
        List.of(
            "2:SampleController.create",
            "2:SampleService.place",
            "2:SampleRepository.save",
            "3:SampleRepository.save",
            "3:SampleService.place",
            "3:SampleController.create"),
        symbols());
    assertEquals(sink.frames.get(0).id, sink.frames.get(1).parent);
    assertEquals(sink.frames.get(1).id, sink.frames.get(2).parent);
    assertEquals("dev.xtrace.agent.runtime.testapp.SampleRepository", sink.frames.get(2).type);
    assertTrue(sink.frames.get(2).descriptor.startsWith("(Ljava/lang/String;)"));
  }

  @Test
  void propagatedExceptionIsFrameThrowAtEveryFrameItCrosses() throws Exception {
    assertTrue(BootstrapBridge.requestStart("POST", "/orders"));
    assertThrows(IllegalStateException.class, () -> call(controller, "create", "boom"));
    BootstrapBridge.requestEnd(0, true);
    assertEquals(
        List.of(
            "2:SampleController.create",
            "2:SampleService.place",
            "2:SampleRepository.save",
            "4:SampleRepository.save",
            "4:SampleService.place",
            "4:SampleController.create"),
        symbols());
  }

  @Test
  void caughtExceptionIsNotObservedAsAThrowByTheCaller() throws Exception {
    assertTrue(BootstrapBridge.requestStart("POST", "/orders"));
    assertEquals("recovered", call(controller, "createTolerant", "boom"));
    BootstrapBridge.requestEnd(200, false);
    assertEquals(
        List.of(
            "2:SampleController.createTolerant",
            "2:SampleService.placeTolerant",
            "2:SampleRepository.save",
            "4:SampleRepository.save",
            "3:SampleService.placeTolerant",
            "3:SampleController.createTolerant"),
        symbols());
  }

  @Test
  void accessorsLambdasAndObjectMethodsAreNotProbed() throws Exception {
    assertTrue(BootstrapBridge.requestStart("GET", "/x"));
    Object service =
        controller.getClass().getClassLoader().loadClass(PKG + "SampleService")
            .getDeclaredConstructor().newInstance();
    service.getClass().getMethod("isReady").invoke(service);
    Object supplier = service.getClass().getMethod("deferred", String.class).invoke(service, "v");
    ((java.util.function.Supplier<?>) supplier).get();
    Object repository =
        controller.getClass().getClassLoader().loadClass(PKG + "SampleRepository")
            .getDeclaredConstructor().newInstance();
    repository.getClass().getMethod("getLastSaved").invoke(repository);
    repository.getClass().getMethod("setLastSaved", String.class).invoke(repository, "v");
    repository.toString();
    BootstrapBridge.requestEnd(200, false);
    assertEquals(List.of("2:SampleService.deferred", "3:SampleService.deferred"), symbols());
  }

  @Test
  void noRequestContextMeansNoFramesAndNoFailure() throws Exception {
    assertEquals("ABC", call(controller, "create", "abc"));
    assertTrue(sink.frames.isEmpty());
  }

  @Test
  void sinkFailureNeverChangesTheApplicationResult() throws Exception {
    assertTrue(BootstrapBridge.requestStart("POST", "/orders"));
    sink.failFrames = true;
    assertEquals("ABC", call(controller, "create", "abc"));
    BootstrapBridge.requestEnd(201, false);
    assertFalse(BootstrapBridge.hasContext());
  }

  @Test
  void matcherSkipsSyntheticBridgeAbstractAndNative() {
    var matcher = FixtureInstrumentation.frameMethods();
    TypeDescription service =
        TypePool.Default.of(getClass().getClassLoader()).describe(PKG + "SampleService").resolve();
    List<String> selected = new ArrayList<>();
    service.getDeclaredMethods().stream()
        .filter(matcher::matches)
        .forEach(method -> selected.add(method.getName()));
    selected.sort(String::compareTo);
    assertEquals(List.of("deferred", "place", "placeTolerant", "shout"), selected);
  }

  private record Frame(
      String id, String parent, int kind, String symbol, String type, String descriptor) {}

  private static final class CapturingSink implements BridgeSink {
    private final List<Frame> frames = new ArrayList<>();
    private boolean failFrames;
    private int counter;

    @Override
    public boolean offerStart(String id, long ns, String method, String route) {
      return true;
    }

    @Override
    public boolean offerEvent(
        String id, String event, String parent, int kind, String symbol, long ns, int detail) {
      if (kind == BridgeEventKind.FRAME_EXIT || kind == BridgeEventKind.FRAME_THROW) {
        frames.add(new Frame(event, parent, kind, symbol, null, null));
      }
      return true;
    }

    @Override
    public boolean offerFrameEvent(
        String id, String event, String parent, int kind, String symbol, long ns, int detail,
        Class<?> type, String method, String descriptor) {
      if (failFrames) throw new IllegalStateException("test-only sink failure");
      frames.add(new Frame(event, parent, kind, symbol, type.getName(), descriptor));
      return true;
    }

    @Override
    public boolean offerFinish(String id, long started, long finished, int status, long dropped) {
      return true;
    }

    @Override
    public void reportIncomplete(int failureKind) {}
  }

  private static final class Isolated extends ClassLoader {
    private final Map<String, byte[]> definitions;

    Isolated(ClassLoader parent, Map<String, byte[]> definitions) {
      super(parent);
      this.definitions = definitions;
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
      synchronized (getClassLoadingLock(name)) {
        Class<?> loaded = findLoadedClass(name);
        if (loaded == null && definitions.containsKey(name)) {
          byte[] bytes = definitions.get(name);
          loaded = defineClass(name, bytes, 0, bytes.length);
        }
        if (loaded != null) {
          if (resolve) resolveClass(loaded);
          return loaded;
        }
      }
      return super.loadClass(name, resolve);
    }
  }
}
