import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import type { SourceBindingName, SourceFacts } from "./runtime/events.cjs";

/**
 * Authored-source resolution for compiled TypeScript (NG-09 basics).
 *
 * Reads the `//# sourceMappingURL` of a generated file (sibling `.map` or a base64 data URI),
 * decodes the mappings with a small VLQ reader and answers with the authored repo-relative
 * position. It never enables `--enable-source-maps`, never touches `Error.stack`, and it never
 * claims more than it saw: a generated position with no map is `source-map-absent`, one with a
 * map that cannot place it inside the repository is `source-map-unresolved`.
 */

const MAX_MAP_BYTES = 8 * 1024 * 1024;
const MAX_SOURCE_BYTES = 8 * 1024 * 1024;
const MAP_COMMENT = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)\s*$/gm;
const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export interface SourceMapOptions {
  /** Absolute repository root; an authored file outside it is never reported. */
  repoRoot: string;
  /** Hash of the authored file's bytes (64 lowercase hex), computed where hashing is available. */
  hashContent?: (bytes: Uint8Array) => string;
}

export interface SourceResolution {
  binding: SourceBindingName;
  /** Present only for bindings that carry a position (`observed-unattested`). */
  facts?: SourceFacts;
  /** Stable reason for a non-attested binding; never an exception message or a path. */
  reason?: "no_source_map_comment" | "source_map_unreadable" | "source_map_invalid" | "position_unmapped" | "authored_outside_repo" | "authored_unreadable";
}

interface DecodedMap {
  sources: string[];
  /** Per generated line, segments sorted by generated column. */
  lines: Array<Array<{ column: number; source: number; line: number; sourceColumn: number }>>;
  sourceRoot: string;
}

const cache = new Map<string, { stamp: string; map: DecodedMap | undefined }>();

/**
 * Maps a 1-based generated line/column in `generatedFile` to its authored position.
 * `observed-unattested`: the adapter read the authored file itself; only a later attestation of the
 * repository revision can upgrade it to `verified`.
 */
export function resolveAuthoredSource(generatedFile: string, line: number, column: number, options: SourceMapOptions): SourceResolution {
  let generatedSource: string;
  try {
    if (statSync(generatedFile).size > MAX_SOURCE_BYTES) return { binding: "source-map-absent", reason: "source_map_unreadable" };
    generatedSource = readFileSync(generatedFile, "utf8");
  } catch {
    return { binding: "source-map-absent", reason: "source_map_unreadable" };
  }
  // The last comment is the one tools honour.
  const comment = [...generatedSource.matchAll(MAP_COMMENT)].at(-1);
  if (!comment) return { binding: "source-map-absent", reason: "no_source_map_comment" };
  const loaded = loadMap(comment[1]!, generatedFile);
  if (loaded === "unreadable") return { binding: "source-map-absent", reason: "source_map_unreadable" };
  if (loaded === undefined) return { binding: "source-map-unresolved", reason: "source_map_invalid" };

  const segment = lookup(loaded, line - 1, column - 1);
  if (!segment) return { binding: "source-map-unresolved", reason: "position_unmapped" };
  const declared = loaded.sources[segment.source];
  if (declared === undefined) return { binding: "source-map-unresolved", reason: "source_map_invalid" };

  const authored = resolve(dirname(generatedFile), loaded.sourceRoot, declared);
  if (!existsSync(authored)) return { binding: "source-map-unresolved", reason: "authored_unreadable" };
  const repoPath = repoRelative(authored, options.repoRoot);
  if (repoPath === undefined) return { binding: "source-map-unresolved", reason: "authored_outside_repo" };

  let hash = "";
  if (options.hashContent) {
    try {
      if (statSync(authored).size > MAX_SOURCE_BYTES) return { binding: "source-map-unresolved", reason: "authored_unreadable" };
      hash = options.hashContent(readFileSync(authored));
    } catch {
      return { binding: "source-map-unresolved", reason: "authored_unreadable" };
    }
    if (!/^[0-9a-f]{64}$/.test(hash)) return { binding: "source-map-unresolved", reason: "authored_unreadable" };
  } else if (!existsSync(authored)) {
    return { binding: "source-map-unresolved", reason: "authored_unreadable" };
  }
  const authoredLine = segment.line + 1;
  const authoredColumn = segment.sourceColumn + 1;
  return {
    binding: "observed-unattested",
    facts: {
      binding: "observed-unattested",
      path: repoPath,
      startLine: authoredLine,
      startColumn: authoredColumn,
      endLine: authoredLine,
      endColumn: authoredColumn,
      contentHash: hash,
    },
  };
}

/** Repo-relative POSIX path, only when the real path stays inside the real repository root. */
export function repoRelative(file: string, repoRoot: string): string | undefined {
  try {
    const root = realpathSync(repoRoot);
    const real = realpathSync(file);
    const rel = relative(root, real);
    if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return undefined;
    return rel.split(sep).join("/");
  } catch {
    return undefined;
  }
}

function loadMap(reference: string, generatedFile: string): DecodedMap | undefined | "unreadable" {
  let text: string;
  let stamp: string;
  if (reference.startsWith("data:")) {
    const match = /^data:application\/json(?:;charset=[^;,]+)?;base64,(.*)$/s.exec(reference);
    if (!match) return undefined;
    text = Buffer.from(match[1]!, "base64").toString("utf8");
    stamp = `data:${text.length}`;
  } else {
    if (/^[a-z][a-z0-9+.-]*:/i.test(reference)) return "unreadable";
    try {
      const mapFile = resolve(dirname(generatedFile), decodeURIComponent(reference));
      const info = statSync(mapFile);
      if (info.size > MAX_MAP_BYTES) return "unreadable";
      stamp = `${info.size}:${info.mtimeMs}`;
      const hit = cache.get(mapFile);
      if (hit && hit.stamp === stamp) return hit.map;
      text = readFileSync(mapFile, "utf8");
      const decoded = decode(text);
      cache.set(mapFile, { stamp, map: decoded });
      return decoded;
    } catch {
      return "unreadable";
    }
  }
  return decode(text);
}

function decode(text: string): DecodedMap | undefined {
  try {
    const raw = JSON.parse(text) as { version?: unknown; sources?: unknown; mappings?: unknown; sourceRoot?: unknown; sections?: unknown };
    if (raw.version !== 3 || raw.sections !== undefined || !Array.isArray(raw.sources) || typeof raw.mappings !== "string") return undefined;
    const sources = raw.sources.map((value) => String(value));
    const lines: DecodedMap["lines"] = [];
    let source = 0;
    let originalLine = 0;
    let originalColumn = 0;
    for (const lineText of raw.mappings.split(";")) {
      const segments: DecodedMap["lines"][number] = [];
      let column = 0;
      for (const part of lineText.split(",")) {
        if (part === "") continue;
        const fields = vlq(part);
        if (!fields || fields.length < 4) { if (fields && fields.length === 1) column += fields[0]!; continue; }
        column += fields[0]!;
        source += fields[1]!;
        originalLine += fields[2]!;
        originalColumn += fields[3]!;
        if (column < 0 || source < 0 || source >= sources.length || originalLine < 0 || originalColumn < 0) return undefined;
        segments.push({ column, source, line: originalLine, sourceColumn: originalColumn });
      }
      lines.push(segments);
    }
    return { sources, lines, sourceRoot: typeof raw.sourceRoot === "string" ? raw.sourceRoot : "" };
  } catch {
    return undefined;
  }
}

function vlq(text: string): number[] | undefined {
  const out: number[] = [];
  let value = 0;
  let shift = 0;
  for (const char of text) {
    const digit = BASE64.indexOf(char);
    if (digit < 0) return undefined;
    value += (digit & 31) * 2 ** shift;
    if (digit & 32) { shift += 5; if (shift > 30) return undefined; continue; }
    out.push(value % 2 === 1 ? -(value - 1) / 2 : value / 2);
    value = 0;
    shift = 0;
  }
  return shift === 0 ? out : undefined;
}

/** Last segment at or before the generated column on that line (the usual source-map lookup). */
function lookup(map: DecodedMap, line: number, column: number): DecodedMap["lines"][number][number] | undefined {
  const segments = map.lines[line];
  if (!segments || segments.length === 0) return undefined;
  let found: DecodedMap["lines"][number][number] | undefined;
  for (const segment of segments) {
    if (segment.column > column) break;
    found = segment;
  }
  return found;
}
