package demo.proxy;

/** Both return descriptors are real methods of the generated JDK proxy. */
public interface CovariantRepository extends demo.framework.RepositoryProxyFactory.CovariantFinder {
  @Override
  String read();
}
