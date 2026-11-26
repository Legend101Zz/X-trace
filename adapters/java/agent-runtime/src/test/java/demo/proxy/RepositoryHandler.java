package demo.proxy;

import dev.xtrace.agent.bootstrap.BootstrapBridge;
import dev.xtrace.agent.bootstrap.JdbcOperation;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

/** Repository-style handler used behind real generated JDK proxies in the capture probe. */
public class RepositoryHandler implements InvocationHandler {
  @Override
  public Object invoke(Object proxy, Method method, Object[] arguments) {
    if (method.getName().equals("fail")) throw new IllegalStateException("private-message-canary");
    if (method.getName().equals("toString")) return "repository";
    if (method.getName().equals("secret")) return "stored";
    if (method.getName().equals("nothing")) return null;
    var database = BootstrapBridge.databaseStart(JdbcOperation.H2_UPDATE);
    BootstrapBridge.databaseEnd(database, false);
    return arguments[0];
  }
}
