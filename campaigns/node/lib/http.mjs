// HTTP client that records every call for the campaign receipt.
import { sha256Hex, canonicalJson } from "./canonical.mjs";

export class Recorder {
  constructor(baseUrl, normalizer) {
    this.baseUrl = baseUrl;
    this.norm = normalizer;
    this.calls = [];
  }

  /**
   * label: stable human name of the call; route: route template (no ids) used in the
   * fingerprint; project(body) -> semantic projection of the parsed body (default: whole body).
   */
  async call(label, method, path, { route, token, body, headers = {}, project, raw, timeoutMs = 20000 } = {}) {
    const h = { ...headers };
    let payload;
    if (body !== undefined) {
      payload = typeof body === "string" ? body : JSON.stringify(body);
      h["content-type"] ||= "application/json";
    }
    if (token) h.authorization = `Bearer ${token}`;
    const t0 = performance.now();
    let res;
    let text = "";
    try {
      res = await fetch(this.baseUrl + path, { method, headers: h, body: payload, signal: AbortSignal.timeout(timeoutMs) });
      text = await res.text();
    } catch (e) {
      const rec = { label, method, route: route || path, status: 0, error: e.name, durationMs: Math.round(performance.now() - t0) };
      this.calls.push(rec);
      return { status: 0, json: null, text: "", rec };
    }
    const durationMs = Math.round(performance.now() - t0);
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    const semantic = json !== null ? (project ? project(json, res.status) : json) : text.length ? { nonJson: this.norm.string(text).slice(0, 200) } : null;
    const normalized = this.norm.value(semantic);
    const rec = {
      label,
      method,
      route: route || path,
      status: res.status,
      requestDigest: payload === undefined ? null : sha256Hex(this.norm.string(payload)),
      responseBytes: Buffer.byteLength(text),
      responseBodyDigest: sha256Hex(text),
      normalizedBodyDigest: sha256Hex(canonicalJson(normalized)),
      normalizedBody: normalized,
      durationMs,
    };
    this.calls.push(rec);
    return { status: res.status, json, text, rec, headers: res.headers };
  }

  take() {
    const c = this.calls;
    this.calls = [];
    return c;
  }
}
