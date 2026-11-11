package dev.xtrace.agent.runtime;

import dev.xtrace.agent.bootstrap.BridgeEventKind;
import dev.xtrace.agent.bootstrap.ProxyBridge;
import dev.xtrace.agent.runtime.line.ValueSanitizer;
import dev.xtrace.agent.runtime.line.ValueSnapshot;
import dev.xtrace.agent.runtime.line.ValueSnapshot.NameOrigin;
import dev.xtrace.agent.runtime.line.ValueSnapshot.Role;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Bounded proxy metadata and sanitized snapshots. Application objects never enter the queue. */
final class ProxyCaptureSink implements ProxyBridge.Sink {
  private final BoundedEventQueue queue;
  private final ApplicationScope scope;
  private final boolean focused;
  private volatile boolean active = true;
  private final ClassValue<Map<Method, Optional<ProxyBridge.Call>>> declarations = new ClassValue<>() {
    @Override
    protected Map<Method, Optional<ProxyBridge.Call>> computeValue(Class<?> type) {
      return new ConcurrentHashMap<>();
    }
  };

  ProxyCaptureSink(BoundedEventQueue queue, ApplicationScope scope, boolean focused) {
    this.queue = queue;
    this.scope = scope;
    this.focused = focused;
  }

  void close() {
    active = false;
    ProxyBridge.disable(this);
  }

  @Override
  public ProxyBridge.Call resolve(Object proxy, Method method) {
    if (!active || proxy == null || method == null || !Proxy.isProxyClass(proxy.getClass())
        || method.getDeclaringClass() == Object.class) return null;
    Map<Method, Optional<ProxyBridge.Call>> cache = declarations.get(proxy.getClass());
    Optional<ProxyBridge.Call> known = cache.get(method);
    if (known != null) return known.orElse(null);
    // A generated proxy has a finite method set, additionally capped against hostile classes.
    // Only first resolution takes this per-class lock; hits never acquire loader monitors or
    // rebuild descriptors. The ClassValue also lets an unloaded proxy release its metadata.
    synchronized (cache) {
      known = cache.get(method);
      if (known != null) return known.orElse(null);
      if (cache.size() >= 1024) return null;
      try {
        Method found = find(proxy.getClass(), method);
        ProxyBridge.Call call = found == null ? null : boundary(found);
        ProxyDiagnostics.resolution(proxy.getClass(), method, call == null ? null : call.symbol(),
            call == null ? "no_declaration" : "resolved");
        cache.put(method, Optional.ofNullable(call));
        return call;
      } catch (RuntimeException | LinkageError failure) {
        ProxyDiagnostics.resolution(proxy.getClass(), method, null, "resolution_failed");
        throw failure;
      }
    }
  }

  private ProxyBridge.Call boundary(Method method) {
    SourceAttestation.SourceInfo observed = ProxyInterfaceSources.lookup(method);
    SourceAttestation.SourceInfo source = observed.path() != null && utf8(observed.path()) > 256
        ? SourceAttestation.SourceInfo.unavailable(5) : observed;
    var parameters = focused ? method.getParameters() : new java.lang.reflect.Parameter[0];
    return new ProxyBridge.Call((recordingId, eventId, parentId, kind, symbol, ns,
        declaration, arguments, result, thrown) -> offer(recordingId, eventId, parentId,
            kind, symbol, ns, declaration, source, parameters, arguments, result, thrown),
        method, method.getDeclaringClass().getName() + "." + method.getName());
  }

  private Method find(Class<?> proxy, Method method) {
    List<Class<?>> contracts = new ArrayList<>(List.of(proxy.getInterfaces()));
    for (int index = 0; index < contracts.size() && index < 256; index++) {
      Class<?> contract = contracts.get(index);
      for (Class<?> parent : contract.getInterfaces()) {
        if (contracts.size() < 256 && !contracts.contains(parent)) contracts.add(parent);
      }
      if (scope.verdict(contract) != ApplicationScope.APPLICATION) continue;
      try {
        Method declaration = contract.getMethod(method.getName(), method.getParameterTypes());
        // getMethod preserves a framework declaration for inherited CRUD methods. Never invent
        // a declaration on the application interface just because it extends that framework.
        if (!java.lang.reflect.Modifier.isStatic(declaration.getModifiers())) return declaration;
      } catch (NoSuchMethodException ignored) {
        // This method belongs to another interface implemented by the same proxy.
      }
    }
    return null;
  }

  private boolean offer(String recordingId, String eventId, String parentId, int kind,
      String symbol, long monotonicNs, Method method, SourceAttestation.SourceInfo source,
      java.lang.reflect.Parameter[] parameters, Object[] arguments, Object result, Throwable thrown) {
    if (!active || utf8(symbol) > 256) return false;
    List<ValueSnapshot> values = new ArrayList<>();
    int bindingBytes = 0;
    if (focused && kind == BridgeEventKind.FRAME_ENTER && arguments != null) {
      boolean aggregate = arguments.length > 16;
      for (int i = 0; i < Math.min(arguments.length, 16); i++) {
        ValueSnapshot snapshot;
        if (i >= parameters.length || !parameters[i].isNamePresent()) {
          // A synthesized name cannot enforce the name-secret rule, so withhold its value.
          snapshot = ValueSanitizer.noDebugMetadata(i, Role.ARGUMENT);
        } else {
          snapshot = ValueSanitizer.ofRef(parameters[i].getName(), NameOrigin.DECLARED,
              arguments[i], Role.ARGUMENT, ValueSanitizer.Limits.STANDARD);
        }
        int bytes = 128 + utf8(snapshot.name()) + utf8(snapshot.typeName())
            + (snapshot.preview() == null ? 0 : utf8(snapshot.preview()));
        if (bindingBytes + bytes > 4096) {
          aggregate = true;
          break;
        }
        bindingBytes += bytes;
        values.add(snapshot);
      }
      if (aggregate) {
        // A wide argument tuple is represented as a whole unavailable array, using the same
        // safe container policy as other probes. Never silently present a prefix as all args.
        values.clear();
        values.add(ValueSanitizer.ofRef("arguments", NameOrigin.SYNTHESIZED, arguments,
            Role.ARGUMENT, ValueSanitizer.Limits.STANDARD));
      }
    } else if (focused && kind == BridgeEventKind.FRAME_EXIT && method.getReturnType() != void.class) {
      values.add(ValueSanitizer.ofRef("return", NameOrigin.SYNTHESIZED, result,
          Role.RETURN, ValueSanitizer.Limits.STANDARD));
    }
    // At most 16 previews of 256 bytes; account for UTF-8 names/types and snapshot overhead too.
    int bytes = 256 + 3 * (recordingId.length() + eventId.length() + parentId.length()
        + symbol.length() + (source.path() == null ? 0 : source.path().length()));
    for (ValueSnapshot value : values) {
      bytes += 256 + 3 * (value.name().length() + value.typeName().length()
          + (value.preview() == null ? 0 : value.preview().length()));
    }
    String exceptionType = thrown == null ? null : thrown.getClass().getName();
    if (exceptionType != null) {
      if (exceptionType.length() > 200) exceptionType = exceptionType.substring(0, 200);
      bytes += exceptionType.length() * 3;
    }
    return queue.offer(new QueueSignal.Event(recordingId, eventId, parentId, kind, symbol,
        monotonicNs, 0, source.path(), source.startLine(), source.endLine(), source.hash(),
        source.binding(), bytes, exceptionType, null, List.copyOf(values)), false);
  }

  private static int utf8(String text) {
    return text.getBytes(StandardCharsets.UTF_8).length;
  }
}
