package demo.framework;

import dev.xtrace.agent.bootstrap.BootstrapBridge;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * Spring-style interface proxy shape without a Spring dependency on the runtime test classpath.
 * The repository, infrastructure contracts and handler deliberately have different scopes.
 */
public final class RepositoryProxyFactory {
  private RepositoryProxyFactory() {}

  public interface CrudRepository<T> {
    T save(T entity);
  }

  public interface Finder<T, ID> {
    java.util.Optional<T> findById(ID id);
  }

  public interface CovariantFinder {
    Object read();
  }

  public interface SpringProxy {}

  public interface Advised {
    boolean isFrozen();
  }

  public interface DecoratingProxy {
    Class<?> getDecoratedClass();
  }

  public static Object create(Class<?> repository) {
    return Proxy.newProxyInstance(repository.getClassLoader(),
        new Class<?>[] {repository, SpringProxy.class, Advised.class, DecoratingProxy.class},
        new RepositoryHandler(repository));
  }

  private static final class RepositoryHandler implements InvocationHandler {
    private final Class<?> repository;

    RepositoryHandler(Class<?> repository) {
      this.repository = repository;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] arguments) {
      if (method.getDeclaringClass() == Object.class) {
        return switch (method.getName()) {
          case "toString" -> "repository";
          case "hashCode" -> System.identityHashCode(proxy);
          case "equals" -> proxy == arguments[0];
          default -> throw new AssertionError(method.getName());
        };
      }
      if (method.getDeclaringClass() == Advised.class) return false;
      if (method.getDeclaringClass() == DecoratingProxy.class) return repository;
      BootstrapBridge.databaseStart();
      BootstrapBridge.databaseEnd(false);
      if (method.getName().equals("findById")) {
        return ((Integer) arguments[0]) == 1 ? java.util.Optional.of("found") : java.util.Optional.empty();
      }
      return arguments[0];
    }
  }
}
