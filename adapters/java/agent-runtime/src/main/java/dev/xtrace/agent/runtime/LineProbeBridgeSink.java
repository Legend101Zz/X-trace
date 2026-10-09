package dev.xtrace.agent.runtime;

import dev.xtrace.agent.bootstrap.LineSink;
import dev.xtrace.agent.runtime.line.SiteRegistry;
import dev.xtrace.agent.runtime.line.ValueSanitizer;
import dev.xtrace.agent.runtime.line.ValueSanitizer.Limits;
import dev.xtrace.agent.runtime.line.ValueSnapshot;
import dev.xtrace.agent.runtime.line.ValueSnapshot.NameOrigin;
import dev.xtrace.agent.runtime.line.ValueSnapshot.Role;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Focused-mode receiver of line probes. It runs on application threads: values are sanitized here
 * (bounded, redacted, never rendered through {@code toString}) and the finished line event is
 * handed to the nonblocking queue. One pending line per thread; the bridge flushes it before any
 * other event of the request is allocated.
 */
final class LineProbeBridgeSink implements LineSink {
  /** CONTRACTS section 4 focused row: bindings per event. */
  static final int MAX_BINDINGS_PER_EVENT = 32;

  /** Stays under the 16 KiB focused per-event value budget. */
  static final int MAX_PREVIEW_BYTES_PER_EVENT = 14 * 1024;

  private final RuntimeBridgeSink events;
  private final SiteRegistry registry;
  private final ThreadLocal<Pending> pending = ThreadLocal.withInitial(Pending::new);
  /** Per-site source facts: the lookup takes a global lock, so each site pays it once. */
  private final java.util.concurrent.ConcurrentHashMap<Integer, SourceAttestation.SourceInfo>
      sources = new java.util.concurrent.ConcurrentHashMap<>();

  private static final SourceAttestation.SourceInfo NO_SOURCE =
      SourceAttestation.SourceInfo.unavailable(0);

  private final AtomicLong withoutSource = new AtomicLong();
  private final AtomicLong rejected = new AtomicLong();

  LineProbeBridgeSink(RuntimeBridgeSink events, SiteRegistry registry) {
    this.events = events;
    this.registry = registry;
  }

  /** Line probes whose site could not be tied to a source file (no event is claimed for them). */
  long linesWithoutSource() {
    return withoutSource.get();
  }

  /** Line events the queue refused (bounded; counted by the queue as shed). */
  long linesRejected() {
    return rejected.get();
  }

  @Override
  public void line(
      String recordingId, String eventId, String parentEventId, int siteId, long monotonicNs) {
    flush();
    Pending p = pending.get();
    p.active = true;
    p.collecting = false;
    p.recordingId = recordingId;
    p.eventId = eventId;
    p.parentEventId = parentEventId;
    p.siteId = siteId;
    p.monotonicNs = monotonicNs;
    p.values.clear();
    p.previewBytes = 0;
  }

  @Override
  public void valuesBegin(int siteId) {
    Pending p = pending.get();
    p.collecting = p.active && p.siteId == siteId;
  }

  @Override
  public void valueInt(int slot, int nameId, int value) {
    SiteRegistry.Name name = nameOf(nameId);
    if (name != null) add(ValueSanitizer.ofInt(name, value, Role.LOCAL, Limits.FOCUSED));
  }

  @Override
  public void valueLong(int slot, int nameId, long value) {
    SiteRegistry.Name name = nameOf(nameId);
    if (name != null) add(ValueSanitizer.ofLong(name, value, Role.LOCAL, Limits.FOCUSED));
  }

  @Override
  public void valueFloat(int slot, int nameId, float value) {
    SiteRegistry.Name name = nameOf(nameId);
    if (name != null) add(ValueSanitizer.ofFloat(name, value, Role.LOCAL, Limits.FOCUSED));
  }

  @Override
  public void valueDouble(int slot, int nameId, double value) {
    SiteRegistry.Name name = nameOf(nameId);
    if (name != null) add(ValueSanitizer.ofDouble(name, value, Role.LOCAL, Limits.FOCUSED));
  }

  @Override
  public void valueRef(int nameId, int role, Object value) {
    SiteRegistry.Name name = nameOf(nameId);
    if (name == null) return;
    add(ValueSanitizer.ofRef(name.name(), NameOrigin.DECLARED, value, roleOf(role), Limits.FOCUSED));
  }

  @Override
  public void valuesEnd() {
    pending.get().collecting = false;
  }

  @Override
  public void flush() {
    Pending p = pending.get();
    if (!p.active) return;
    p.active = false;
    p.collecting = false;
    SiteRegistry.Site site = registry.site(p.siteId);
    if (site == null) return;
    SourceAttestation.SourceInfo source = sources.get(p.siteId);
    if (source == null) {
      SourceAttestation.SourceInfo found =
          SourceIdentity.lookupLine(site.classInternalName(), site.line());
      source = found == null ? NO_SOURCE : found;
      sources.putIfAbsent(p.siteId, source);
    }
    if (source == NO_SOURCE) {
      withoutSource.incrementAndGet();
      return;
    }
    String binary = site.classInternalName().replace('/', '.');
    int dot = binary.lastIndexOf('.');
    String symbol = (dot < 0 ? binary : binary.substring(dot + 1)) + "." + site.method();
    if (!events.offerLineEvent(
        p.recordingId, p.eventId, p.parentEventId, symbol, p.monotonicNs, source, p.values)) {
      rejected.incrementAndGet();
    }
  }

  private SiteRegistry.Name nameOf(int nameId) {
    Pending p = pending.get();
    return p.collecting ? registry.name(nameId) : null;
  }

  private void add(ValueSnapshot snapshot) {
    Pending p = pending.get();
    if (p.values.size() >= MAX_BINDINGS_PER_EVENT) return;
    int bytes = snapshot.preview() == null ? 0 : snapshot.preview().length() * 3;
    if (p.previewBytes + bytes > MAX_PREVIEW_BYTES_PER_EVENT) return;
    p.previewBytes += bytes;
    p.values.add(snapshot);
  }

  private static Role roleOf(int wire) {
    return switch (wire) {
      case 1 -> Role.ARGUMENT;
      case 2 -> Role.RETURN;
      case 4 -> Role.EXCEPTION;
      case 5 -> Role.RECEIVER;
      default -> Role.LOCAL;
    };
  }

  private static final class Pending {
    boolean active;
    boolean collecting;
    String recordingId;
    String eventId;
    String parentEventId;
    int siteId;
    long monotonicNs;
    int previewBytes;
    final List<ValueSnapshot> values = new ArrayList<>(8);
  }
}
