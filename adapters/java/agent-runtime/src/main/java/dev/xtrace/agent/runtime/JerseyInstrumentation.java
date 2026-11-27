package dev.xtrace.agent.runtime;

import static net.bytebuddy.matcher.ElementMatchers.hasDescriptor;
import static net.bytebuddy.matcher.ElementMatchers.isBridge;
import static net.bytebuddy.matcher.ElementMatchers.isSynthetic;
import static net.bytebuddy.matcher.ElementMatchers.named;
import static net.bytebuddy.matcher.ElementMatchers.not;

import dev.xtrace.agent.bootstrap.JerseyBridge;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProtectionDomain;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.jar.Manifest;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

/** Launch-only Jersey 3.1.11 probes. Match the class bytes actually supplied to the JVM. */
final class JerseyInstrumentation {
  static final String SERVICE = "org/glassfish/jersey/servlet/ServletContainer";
  static final String COMPONENT = "org/glassfish/jersey/servlet/WebComponent";
  static final String INVOKER = "org/glassfish/jersey/server/model/ResourceMethodInvoker";
  private static final String SERVICE_HASH = "933e70fb8cf969087bd8b862bbce67a54cd39e9533e91e095f8682d0fb43bada";
  private static final String COMPONENT_HASH = "d437beb05b3ccaf0dcace45d11d25559dbcec5b3224aee601338abdd60d6ca11";
  private static final String INVOKER_HASH = "b5ec8f9270cfefa2f634d7c40547a4c8f1c4ff3575db9f4cbc63563692f7d63e";
  private static final String SERVICE_DESCRIPTOR =
      "(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;)V";
  private static final String BIND_DESCRIPTOR =
      "(Lorg/glassfish/jersey/server/ContainerRequest;Ljakarta/servlet/http/HttpServletRequest;"
          + "Ljakarta/servlet/http/HttpServletResponse;Lorg/glassfish/jersey/servlet/internal/ResponseWriter;)V";
  private static final String APPLY_DESCRIPTOR =
      "(Lorg/glassfish/jersey/server/internal/process/RequestProcessingContext;)"
          + "Lorg/glassfish/jersey/server/ContainerResponse;";

  // Loading an unqualified framework library says nothing about application probes
  // or which individual requests used Jersey. Keep these notices process-scoped.
  private static final AtomicBoolean UNQUALIFIED = new AtomicBoolean();
  private static final AtomicBoolean PROBE_UNAVAILABLE = new AtomicBoolean();

  private JerseyInstrumentation() {}

  static void reportCoverageAtShutdown() {
    if (UNQUALIFIED.getAndSet(false)) {
      System.err.println("{\"code\":\"XTR-JAVA-INSTRUMENTATION\","
          + "\"message\":\"Jersey framework class image or bundle identity did not qualify\"}");
    }
    if (PROBE_UNAVAILABLE.getAndSet(false)) {
      System.err.println("{\"code\":\"XTR-JAVA-INSTRUMENTATION\","
          + "\"message\":\"Jersey framework probe installation unavailable\"}");
    }
  }

  static void install(Instrumentation instrumentation) {
    ClassFileTransformer probes = new AgentBuilder.Default()
        .disableClassFormatChanges()
        .type(named(SERVICE.replace('/', '.')))
        .transform((type, description, loader, module, domain) -> type.visit(
            Advice.to(ServiceAdvice.class).on(named("service").and(hasDescriptor(SERVICE_DESCRIPTOR)))))
        .type(named(COMPONENT.replace('/', '.')))
        .transform((type, description, loader, module, domain) -> type.visit(
            Advice.to(BindAdvice.class).on(named("initContainerRequest").and(hasDescriptor(BIND_DESCRIPTOR)))))
        .type(named(INVOKER.replace('/', '.')))
        .transform((type, description, loader, module, domain) -> type.visit(
            Advice.to(DispatchAdvice.class).on(named("apply").and(hasDescriptor(APPLY_DESCRIPTOR))
                .and(not(isBridge())).and(not(isSynthetic())))))
        .makeRaw();
    instrumentation.addTransformer(new ClassFileTransformer() {
      @Override
      public byte[] transform(Module module, ClassLoader loader, String name, Class<?> redefined,
          ProtectionDomain domain, byte[] bytes) {
        if (name == null || redefined != null) return null;
        String expected = switch (name) {
          case SERVICE -> SERVICE_HASH;
          case COMPONENT -> COMPONENT_HASH;
          case INVOKER -> INVOKER_HASH;
          default -> null;
        };
        if (expected == null) return null;
        try {
          String inputHash = hash(bytes);
          BundleEvidence bundle = readBundle(name, domain);
          if (loader == null || bundle == null || !bundle.named()) {
            UNQUALIFIED.set(true);
            return null;
          }
          boolean imageMatches = expected.equals(inputHash);
          if (!imageMatches || !bundle.supported()) {
            UNQUALIFIED.set(true);
            String decision = imageMatches ? "version-excluded"
                : bundle.supported() ? "image-excluded" : "image-and-version-excluded";
            traceDecision(name, decision, inputHash, bundle.manifestHash());
            return null;
          }
          byte[] result = probes.transform(module, loader, name, null, domain, bytes);
          if (result != null) {
            traceDecision(name, "qualified", inputHash, bundle.manifestHash());
            return result;
          }
        } catch (Exception | LinkageError ignored) {
          // This failure belongs to a framework probe; application probes remain independent.
        }
        PROBE_UNAVAILABLE.set(true);
        return null;
      }
    });
  }

  private record BundleEvidence(boolean named, boolean supported, String manifestHash) {}

  // Opt-in qualification trace. Only known target names, fixed decisions and digests
  // of the actual transform input and its origin manifest leave the transformer.
  private static void traceDecision(String name, String decision, String inputHash, String manifestHash) {
    try {
      if (!Boolean.getBoolean("xtrace.jersey.probeEvidence")) return;
      String target = switch (name) {
        case SERVICE -> "service";
        case COMPONENT -> "component";
        case INVOKER -> "invoker";
        default -> throw new IllegalArgumentException("unknown Jersey target");
      };
      System.err.println("XTRACE-JERSEY-PROBE/1 " + target + " " + decision + " " + inputHash + " " + manifestHash);
    } catch (RuntimeException ignored) {
      // A disabled or failing diagnostic stream must not change instrumentation.
    }
  }

  // Adjacent Jersey releases contain identical dispatch classes. Read the manifest of the
  // exact local code source, never a first-match META-INF resource from the class loader.
  private static BundleEvidence readBundle(String name, ProtectionDomain domain)
      throws IOException, NoSuchAlgorithmException {
    if (domain == null || domain.getCodeSource() == null) return null;
    URL source = domain.getCodeSource().getLocation();
    if (source == null || !source.getHost().isEmpty()) return null;
    String location = source.toExternalForm();
    URL manifest;
    if (source.getProtocol().equals("file") && location.endsWith(".jar")) {
      manifest = new URL("jar:" + location + "!/META-INF/MANIFEST.MF");
    } else if (source.getProtocol().equals("jar") && location.startsWith("jar:nested:/")
        && !location.startsWith("jar:nested://") && location.endsWith(".jar!/")) {
      manifest = new URL(source, "META-INF/MANIFEST.MF");
    } else {
      return null;
    }
    try (InputStream stream = manifest.openStream()) {
      byte[] data = stream.readNBytes(128 * 1024 + 1);
      if (data.length > 128 * 1024) return null;
      var attributes = new Manifest(new ByteArrayInputStream(data)).getMainAttributes();
      String bundle = INVOKER.equals(name) ? "org.glassfish.jersey.core.jersey-server"
          : "org.glassfish.jersey.containers.jersey-container-servlet-core";
      String version = attributes.getValue("Bundle-Version");
      if (version == null || version.isEmpty()) return null;
      return new BundleEvidence(bundle.equals(attributes.getValue("Bundle-SymbolicName")),
          "3.1.11".equals(version), hash(data));
    }
  }

  private static String hash(byte[] bytes) throws NoSuchAlgorithmException {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }

  public static final class ServiceAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static Object enter(@Advice.Origin Class<?> type, @Advice.Argument(0) Object request) {
      return JerseyBridge.serviceEnter(type, request);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter Object owner, @Advice.Thrown Throwable thrown) {
      JerseyBridge.serviceExit(owner, thrown);
    }
  }

  public static final class BindAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static void enter(@Advice.Origin Class<?> type, @Advice.Argument(0) Object jerseyRequest,
        @Advice.Argument(1) Object servletRequest) {
      JerseyBridge.bindRequest(type, jerseyRequest, servletRequest);
    }
  }

  public static final class DispatchAdvice {
    @Advice.OnMethodEnter(suppress = Throwable.class)
    public static boolean enter(@Advice.This Object invoker, @Advice.Argument(0) Object context) {
      return JerseyBridge.dispatchEnter(invoker, context);
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class, suppress = Throwable.class)
    public static void exit(@Advice.Enter boolean recorded, @Advice.Return Object response,
        @Advice.Thrown Throwable thrown) {
      if (recorded) JerseyBridge.dispatchExit(response, thrown);
    }
  }
}
