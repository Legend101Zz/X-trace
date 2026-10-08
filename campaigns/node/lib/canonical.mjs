// Canonical JSON + digests shared by the Node campaign harnesses.
import { createHash } from "node:crypto";

export function sha256Hex(data) {
  return createHash("sha256").update(data).digest("hex");
}

export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  return (
    "{" +
    Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + canonicalJson(value[k]))
      .join(",") +
    "}"
  );
}

const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const ULID_PREFIXED = /\b[a-z]{2,12}_[0-9A-HJKMNP-TV-Z]{26}\b/g; // medusa ids: prod_01H...
const ISO_TS = /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/g;
const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;

/**
 * Replaces volatile values (ids, timestamps, tokens) with stable placeholders
 * numbered by first appearance within one Normalizer, so equal semantics give
 * equal output across resets. Extra literals (e.g. a per-run suffix) can be
 * registered with `addLiteral`.
 */
export class Normalizer {
  constructor() {
    this.maps = new Map();
    this.literals = [];
  }
  addLiteral(literal, label) {
    if (literal) this.literals.push([String(literal), label]);
  }
  _ph(kind, raw) {
    if (!this.maps.has(kind)) this.maps.set(kind, new Map());
    const m = this.maps.get(kind);
    if (!m.has(raw)) m.set(raw, `<${kind}:${m.size + 1}>`);
    return m.get(raw);
  }
  string(s) {
    let out = s;
    for (const [lit, label] of this.literals) out = out.split(lit).join(`<${label}>`);
    out = out.replace(JWT, () => "<jwt>");
    out = out.replace(ULID_PREFIXED, (m) => this._ph("ulid", m));
    out = out.replace(UUID, (m) => this._ph("uuid", m.toLowerCase()));
    out = out.replace(ISO_TS, () => "<ts>");
    return out;
  }
  value(v, key = "") {
    if (typeof v === "string") return this.string(v);
    if (Array.isArray(v)) return v.map((x) => this.value(x, key));
    if (v && typeof v === "object") {
      const o = {};
      for (const k of Object.keys(v)) o[k] = this.value(v[k], k);
      return o;
    }
    return v;
  }
}
