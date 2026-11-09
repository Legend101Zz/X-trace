package demo.proxy;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/** Interface-only repository: no application implementation exists for boundary probes. */
public interface RepositoryContract extends java.util.function.Function<String, String> {
  // A misleading example is not a declaration: String save(long id);
  String save(String description);
  String save(long id);
  String secret(String password);
  String query(@Param("name") String name);
  Object opaque(Object value);
  <T extends Number> T bounded(T value);
  String wide(String a0, String a1, String a2, String a3, String a4, String a5, String a6,
      String a7, String a8, String a9, String a10, String a11, String a12, String a13,
      String a14, String a15);
  void fail();
  void nothing();

  @Retention(RetentionPolicy.RUNTIME)
  @interface Param {
    String value();
  }
}
