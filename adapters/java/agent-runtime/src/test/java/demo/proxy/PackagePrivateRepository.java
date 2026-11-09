package demo.proxy;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;

/** A non-public contract forces the JDK proxy into the contract's own package and module. */
public final class PackagePrivateRepository {
  private PackagePrivateRepository() {}

  interface Contract {
    String save(String description);
  }

  public static Object create(InvocationHandler handler) {
    return Proxy.newProxyInstance(Contract.class.getClassLoader(), new Class<?>[] {Contract.class}, handler);
  }

  public static String save(Object proxy, String value) {
    return ((Contract) proxy).save(value);
  }
}
