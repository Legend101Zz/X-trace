package dev.xtrace.agent.runtime.line;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

/**
 * Checks that the probe owner exposes the eight static probe methods with the exact descriptors the
 * visitor emits. An instrumented method calling a missing probe would throw
 * {@code NoSuchMethodError} inside application code, which is not fail-open.
 */
public final class ProbeOwnerCheck {
  private ProbeOwnerCheck() {}

  /** Method name and parameter types of every probe the visitor can emit (all return void). */
  private static final Object[][] REQUIRED = {
    {"line", new Class<?>[] {int.class}},
    {"valuesBegin", new Class<?>[] {int.class}},
    {"valueInt", new Class<?>[] {int.class, int.class, int.class}},
    {"valueLong", new Class<?>[] {int.class, int.class, long.class}},
    {"valueFloat", new Class<?>[] {int.class, int.class, float.class}},
    {"valueDouble", new Class<?>[] {int.class, int.class, double.class}},
    {"valueRef", new Class<?>[] {int.class, int.class, Object.class}},
    {"valuesEnd", new Class<?>[] {}},
  };

  /**
   * @param ownerInternalName e.g. {@code dev/xtrace/agent/bootstrap/BootstrapBridge}
   * @param loader loader that application code would resolve the owner through; {@code null} means
   *     the bootstrap class loader
   * @return null when the owner is complete, otherwise a short human-readable reason
   */
  public static String problem(String ownerInternalName, ClassLoader loader) {
    Class<?> owner;
    try {
      owner = Class.forName(ownerInternalName.replace('/', '.'), false, loader);
    } catch (ClassNotFoundException | LinkageError e) {
      return "owner class not found: " + ownerInternalName;
    }
    if (!Modifier.isPublic(owner.getModifiers())) return "owner class is not public";
    for (Object[] r : REQUIRED) {
      String name = (String) r[0];
      Class<?>[] params = (Class<?>[]) r[1];
      Method m;
      try {
        m = owner.getMethod(name, params);
      } catch (NoSuchMethodException | LinkageError e) {
        return "missing probe method " + name;
      }
      if (!Modifier.isStatic(m.getModifiers()) || m.getReturnType() != void.class) {
        return "probe method " + name + " is not static void";
      }
      if (m.getDeclaringClass() != owner) return "probe method " + name + " is inherited";
    }
    return null;
  }
}
