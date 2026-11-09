package demo.proxy;

import demo.framework.RepositoryProxyFactory.CrudRepository;

/** An application finder plus inherited, erased CRUD methods, with no concrete implementation. */
public interface SpringRepository extends CrudRepository<String> {
  String findByName(String name);
}
