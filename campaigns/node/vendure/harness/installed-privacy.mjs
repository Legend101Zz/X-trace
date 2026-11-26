// Bounded exact-value check, not a claim that arbitrary sensitive information is absent.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { zstdDecompressSync } from "node:zlib";
import { need, recordingId } from "./installed-evidence.mjs";

export function judgeVendurePrivacy({ dataHome, readback, diagnostic, witness }) {
  const privateWitness = JSON.parse(fs.readFileSync(witness, "utf8"));
  need(Array.isArray(privateWitness.values) && privateWitness.values.length > 0 && privateWitness.values.length <= 2048);
  const patterns = new Set();
  for (const value of privateWitness.values) {
    need(typeof value === "string" && value.length >= 8 && Buffer.byteLength(value) <= 131072);
    patterns.add(value); patterns.add(JSON.stringify(value).slice(1, -1));
  }
  const needles = [...patterns].map(value => Buffer.from(value));
  const counts = { files: 0, bytes: 0, matches: 0 };
  const visited = new Set();
  const surfaces = {};
  function file(filename, surface) {
    const info = fs.lstatSync(filename);
    need(info.isFile() && info.uid === process.getuid() && info.nlink === 1 && (info.mode & 0o077) === 0);
    need(info.size <= 64 * 1024 * 1024 && counts.files < 4096 && counts.bytes + info.size <= 256 * 1024 * 1024);
    const identity = `${info.dev}:${info.ino}`;
    need(!visited.has(identity)); visited.add(identity);
    const bytes = fs.readFileSync(filename);
    need(bytes.length === info.size);
    const matches = needles.filter(needle => bytes.includes(needle)).length;
    counts.files++; counts.bytes += bytes.length; counts.matches += matches;
    const group = surfaces[surface] ??= { files: 0, bytes: 0, matches: 0 };
    group.files++; group.bytes += bytes.length; group.matches += matches;
  }
  function tree(directory, depth = 0) {
    need(depth <= 16);
    const info = fs.lstatSync(directory);
    need(info.isDirectory() && info.uid === process.getuid() && (info.mode & 0o077) === 0);
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const filename = path.join(directory, entry.name);
      need(!entry.isSymbolicLink());
      if (entry.isDirectory()) tree(filename, depth + 1);
      else file(filename, "persisted");
    }
  }
  tree(dataHome);
  const products = fs.readdirSync(readback).filter(name => /^(cli|api)-[0-9]+\.(json|stderr)$/.test(name));
  need(products.some(name => name.startsWith("cli-")) && products.some(name => name.startsWith("api-")));
  for (const name of products) file(path.join(readback, name), name.startsWith("cli-") ? "cli" : "api");
  // Auth readiness/token transport and raw workload/vendor logs are deliberately outside this product projection.
  file(path.join(readback, "viewer.stderr"), "viewerDiagnostics");
  file(diagnostic, "launcherDiagnostics");
  return { status: counts.matches === 0 ? "passed" : "failed", ...counts, surfaces,
    scope: "exact raw and JSON-escaped request documents, request scalar values of at least eight characters, credentials and observed auth tokens",
    projections: ["persisted-installed-data", "installed-cli", "authenticated-viewer-api", "viewer-stderr", "launcher-stderr"],
    excluded: ["expected-viewer-bootstrap-credential-transport", "private-workload-witness", "vendor-worker-logs", "application-source-and-env"],
    arbitrarySensitiveDataAbsence: "unverified" };
}

// This is the required real-pair entry point. Reconcile the exact project and
// recording IDs against the read-only SQLite file before crediting persisted data.
export function judgeInstalledVendurePrivacy(args) {
  const raw = judgeVendurePrivacy(args);
  const inventory = JSON.parse(fs.readFileSync(path.join(args.readback, "store-inventory.private.json"), "utf8"));
  const projectId = recordingId(inventory.projectId);
  need(Array.isArray(inventory.recordings) && inventory.recordings.length > 0 && inventory.recordings.length <= 400);
  const root = path.join(args.dataHome, "projects", projectId);
  const database = path.join(root, "metadata.sqlite3");
  const bytes = fs.readFileSync(database);
  need(bytes.length >= 100 && bytes.subarray(0, 16).equals(Buffer.from("SQLite format 3\0")));
  const db = new DatabaseSync(database, { readOnly: true });
  const witnesses = JSON.parse(fs.readFileSync(args.witness, "utf8")).values;
  const needles = [...new Set(witnesses.flatMap(value => [value, JSON.stringify(value).slice(1, -1)]))].map(value => Buffer.from(value));
  const seen = new Set();
  let decodedBytes = 0, matches = 0;
  try {
    const project = Buffer.from(projectId.replaceAll("-", ""), "hex");
    const ids = db.prepare("SELECT hex(recording_id) AS id FROM recordings WHERE project_id = ? LIMIT 401").all(project);
    const expected = new Map(inventory.recordings);
    need(expected.size === inventory.recordings.length && ids.length === expected.size);
    const actual = new Set(ids.map(({ id }) => id.toLowerCase()));
    const segments = db.prepare("SELECT object_hash, segment_ordinal, event_count, compressed_bytes, uncompressed_bytes FROM recording_segments WHERE recording_id = ? ORDER BY segment_ordinal LIMIT 4001");
    for (const [id, row] of expected) {
      const hex = recordingId(id).replaceAll("-", "");
      need(actual.has(hex));
      const stored = segments.all(Buffer.from(hex, "hex"));
      need(stored.length > 0 && stored.length === row.segments && stored.length <= 4000);
      let events = 0;
      for (const [ordinal, seg] of stored.entries()) {
        need(seg.segment_ordinal === ordinal && seg.object_hash.length === 32 && seg.event_count > 0);
        events += seg.event_count;
        const address = Buffer.from(seg.object_hash).toString("hex");
        if (seen.has(address)) continue;
        seen.add(address);
        const file = path.join(root, "objects", "b3", address.slice(0, 2), address.slice(2) + ".xtf.zst");
        const info = fs.lstatSync(file);
        need(info.isFile() && info.nlink === 1 && info.uid === process.getuid() && (info.mode & 0o077) === 0);
        need(info.size > 0 && info.size === seg.compressed_bytes && info.size <= 64 * 1024 * 1024);
        need(seg.uncompressed_bytes > 0 && seg.uncompressed_bytes <= 64 * 1024 * 1024);
        need(decodedBytes + seg.uncompressed_bytes + raw.bytes <= 256 * 1024 * 1024);
        const logical = zstdDecompressSync(fs.readFileSync(file), { maxOutputLength: seg.uncompressed_bytes });
        need(logical.length === seg.uncompressed_bytes && logical.subarray(0, 4).equals(Buffer.from("XTF1")));
        decodedBytes += logical.length;
        matches += needles.filter(needle => logical.includes(needle)).length;
      }
      need(events === row.count);
    }
    need(seen.size > 0);
  } finally { db.close(); }
  return { ...raw, status: raw.matches + matches === 0 ? "passed" : "failed",
    decodedSegments: seen.size, decodedBytes, decodedMatches: matches };
}
