package demo.probe;

import dev.xtrace.agent.runtime.line.LineProbeAsmWrapper;
import dev.xtrace.agent.runtime.line.LineProbeConfig;
import dev.xtrace.agent.runtime.line.MethodReport;
import dev.xtrace.agent.runtime.line.ProbeOwnerCheck;
import dev.xtrace.agent.runtime.line.SiteRegistry;
import java.util.ArrayList;
import java.util.List;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.pool.TypePool;

/**
 * Child-JVM entry for the production owner path: the probe owner must resolve through the
 * bootstrap loader (null), exactly as the agent's appended bootstrap search makes it visible.
 */
public final class OwnerProbeMain {
  private OwnerProbeMain() {}

  public static void main(String[] args) throws Exception {
    String owner = "dev/xtrace/agent/bootstrap/BootstrapBridge";
    Class<?> bridge = Class.forName(owner.replace('/', '.'), false, null);
    String problem = ProbeOwnerCheck.problem(owner, null);
    SiteRegistry registry = new SiteRegistry();
    List<MethodReport> reports = new ArrayList<>();
    ClassLoader parent = OwnerProbeMain.class.getClassLoader();
    new ByteBuddy()
        .redefine(
            TypePool.Default.of(parent).describe("demo.probe.Orders").resolve(),
            ClassFileLocator.ForClassLoader.of(parent))
        .visit(
            new LineProbeAsmWrapper(
                LineProbeConfig.focused(owner), registry, t -> null, reports::addAll, null))
        .make();
    System.out.println(
        "RESULT bridgeLoader=" + bridge.getClassLoader() + " problem=" + problem
            + " sites=" + registry.siteCount() + " reports=" + reports);
  }
}
