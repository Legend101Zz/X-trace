package demo.proxy;

import demo.framework.RepositoryProxyFactory.CrudRepository;

/** An application finder plus inherited, erased CRUD methods, with no concrete implementation. */
public interface SpringRepository extends CrudRepository<String>,
    demo.framework.RepositoryProxyFactory.Finder<String, Integer> {
  String findByName(String name);
}
