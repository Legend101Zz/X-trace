package dev.xtrace.agent.runtime.line;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Transform-time registry that turns {@code (class digest, method, descriptor, line)} into the small
 * {@code int} site ids probes pass at run time, and local-variable names into name ids. Site ids and
 * name ids start at 1. Bounded: when full, methods are skipped with an honest reason.
 */
public final class SiteRegistry {
  /** One instrumented line site. */
  public record Site(
      int id,
      String classInternalName,
      byte[] classDigest,
      String method,
      String descriptor,
      int line) {}

  /** A declared local variable name (from the LocalVariableTable). */
  public record Name(int id, String name, String descriptor, int slot) {}

  /** About 22 MB at the limit; a background agent should not carry more. */
  public static final int DEFAULT_MAX_SITES = 250_000;

  private final int maxSites;
  private final AtomicInteger nextSite = new AtomicInteger(1);
  private final AtomicInteger nextName = new AtomicInteger(1);
  private final ConcurrentHashMap<Integer, Site> sites = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<Integer, Name> names = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, Integer> nameIndex = new ConcurrentHashMap<>();
  /** (digest, class, method, descriptor, line, ordinal) to site id: retransforming reuses ids. */
  private final ConcurrentHashMap<String, Integer> siteIndex = new ConcurrentHashMap<>();

  public SiteRegistry() {
    this(DEFAULT_MAX_SITES);
  }

  public SiteRegistry(int maxSites) {
    if (maxSites < 1) throw new IllegalArgumentException("maxSites");
    this.maxSites = maxSites;
  }

  /** True when {@code count} more sites still fit. Advisory under races; {@link #addSite} enforces. */
  public boolean hasRoomFor(int count) {
    return (long) nextSite.get() - 1 + count <= maxSites;
  }

  /** Allocates a site id (ordinal 0), or returns -1 when the registry is full. */
  public int addSite(
      String classInternalName, byte[] classDigest, String method, String descriptor, int line) {
    return addSite(classInternalName, classDigest, method, descriptor, line, 0);
  }

  /**
   * Allocates a site id, or returns -1 when the registry is full. When the class digest is known,
   * the same {@code (digest, class, method, descriptor, line, ordinal)} always yields the same id
   * (retransformation of unchanged bytes does not grow the registry). {@code ordinal} separates
   * several sites of one method that share a line number.
   */
  public int addSite(
      String classInternalName,
      byte[] classDigest,
      String method,
      String descriptor,
      int line,
      int ordinal) {
    String key = null;
    if (classDigest != null) {
      key =
          java.util.HexFormat.of().formatHex(classDigest)
              + '\u0000' + classInternalName + '\u0000' + method + '\u0000' + descriptor
              + '\u0000' + line + '\u0000' + ordinal;
      Integer existing = siteIndex.get(key);
      if (existing != null) return existing;
    }
    int id = nextSite.getAndIncrement();
    if (id > maxSites) {
      nextSite.decrementAndGet();
      return -1;
    }
    Site site = new Site(id, classInternalName, classDigest, method, descriptor, line);
    sites.put(id, site);
    if (key != null) {
      Integer raced = siteIndex.putIfAbsent(key, id);
      if (raced != null) {
        // Another thread registered the same site first: drop ours (the id is simply unused).
        sites.remove(id);
        return raced;
      }
    }
    return id;
  }

  public int addName(String name, String descriptor, int slot) {
    String key = slot + "\u0000" + name + "\u0000" + descriptor;
    Integer existing = nameIndex.get(key);
    if (existing != null) return existing;
    synchronized (this) {
      existing = nameIndex.get(key);
      if (existing != null) return existing;
      int id = nextName.getAndIncrement();
      names.put(id, new Name(id, name, descriptor, slot));
      nameIndex.put(key, id);
      return id;
    }
  }

  public Site site(int id) {
    return sites.get(id);
  }

  public Name name(int id) {
    return names.get(id);
  }

  public int nameCount() {
    return nextName.get() - 1;
  }

  public int siteCount() {
    return sites.size();
  }
}
