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

  private final int maxSites;
  private final AtomicInteger nextSite = new AtomicInteger(1);
  private final AtomicInteger nextName = new AtomicInteger(1);
  private final ConcurrentHashMap<Integer, Site> sites = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<Integer, Name> names = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, Integer> nameIndex = new ConcurrentHashMap<>();

  public SiteRegistry() {
    this(1_000_000);
  }

  public SiteRegistry(int maxSites) {
    if (maxSites < 1) throw new IllegalArgumentException("maxSites");
    this.maxSites = maxSites;
  }

  /** True when {@code count} more sites still fit. Advisory under races; {@link #addSite} enforces. */
  public boolean hasRoomFor(int count) {
    return (long) nextSite.get() - 1 + count <= maxSites;
  }

  /** Allocates a site id, or returns -1 when the registry is full. */
  public int addSite(
      String classInternalName, byte[] classDigest, String method, String descriptor, int line) {
    int id = nextSite.getAndIncrement();
    if (id > maxSites) {
      nextSite.decrementAndGet();
      return -1;
    }
    sites.put(id, new Site(id, classInternalName, classDigest, method, descriptor, line));
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
