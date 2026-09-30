package dev.xtrace.agent.bootstrap;

import java.net.URL;
import java.net.URLClassLoader;

/** Child-first loader that exposes only the JDK and bootstrap bridge to the private runtime. */
final class PrivateAgentClassLoader extends URLClassLoader {
  PrivateAgentClassLoader(URL[] urls) {
    super(urls, ClassLoader.getPlatformClassLoader());
  }

  @Override
  protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
    if (name.startsWith("dev.xtrace.agent.bootstrap.")) {
      return Class.forName(name, false, null);
    }
    if (name.startsWith("java.") || name.startsWith("javax.") || name.startsWith("jdk.")) {
      return super.loadClass(name, resolve);
    }
    synchronized (getClassLoadingLock(name)) {
      Class<?> loaded = findLoadedClass(name);
      if (loaded == null) {
        try {
          loaded = findClass(name);
        } catch (ClassNotFoundException missing) {
          loaded = super.loadClass(name, false);
        }
      }
      if (resolve) resolveClass(loaded);
      return loaded;
    }
  }
}
