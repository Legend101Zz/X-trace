package dev.xtrace.agent.runtime.line;

import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.matcher.ElementMatcher;

/** The common executable policy for focused cursors and their enclosing boundaries. */
public final class ProbeEligibility {
  private ProbeEligibility() {}

  public static String exclusion(int access, String name) {
    if ((access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) return MethodReport.Reasons.NO_CODE;
    if ((access & Opcodes.ACC_BRIDGE) != 0) return MethodReport.Reasons.BRIDGE;
    if ((access & Opcodes.ACC_SYNTHETIC) != 0 && !name.startsWith("lambda$")) {
      return MethodReport.Reasons.SYNTHETIC;
    }
    // Class initializers have no boundary; their entry gap accounts for every omitted cursor.
    if (name.equals("<clinit>")) return MethodReport.Reasons.INITIALIZER;
    return null;
  }

  public static ElementMatcher.Junction<MethodDescription> focused() {
    return new ElementMatcher.Junction.AbstractBase<>() {
      @Override
      public boolean matches(MethodDescription method) {
        return exclusion(method.getModifiers(), method.getInternalName()) == null;
      }
    };
  }
}
