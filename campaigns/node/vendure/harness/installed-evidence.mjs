// Finite read-only evidence. No request identity or worker ancestry is inferred from counts.
import { isDeepStrictEqual } from "node:util";
export function need(ok) { if (!ok) throw new Error("Vendure installed evidence mismatch"); }
export function recordingId(value) {
  need(typeof value === "string" && /^[a-f0-9]{8}-[a-f0-9]{4}-7[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value));
  return value;
}
export async function pages(load, rowsKey, cursorKey, limit, maximum) {
  let cursor;
  const seen = new Set(), result = [];
  for (let page = 0; page < 40; page++) {
    const doc = await load(cursor), rows = doc[rowsKey], next = doc[cursorKey];
    need(Array.isArray(rows) && rows.length <= limit && rows.every(row => row && typeof row === "object"));
    maximum -= rows.length;
    need(maximum >= 0 && (next === null || (typeof next === "string" && next.length > 0 && next.length <= 4096 &&
      !seen.has(next) && rows.length > 0)));
    result.push(doc);
    if (next === null) return result;
    seen.add(next); cursor = next;
  }
  throw new Error("Vendure evidence page bound exhausted");
}
export function keys(paged, rowsKey, idKey) {
  const ids = paged.flatMap(doc => doc[rowsKey].map(row => recordingId(row[idKey])));
  need(new Set(ids).size === ids.length);
  return ids.sort();
}
function lifecycleStatus(value) {
  need(["recording", "finalizing", "complete", "partial", "invalid"].includes(value));
  return value;
}
function reasonList(value) {
  need(Array.isArray(value) && value.length <= 256 && value.every(reason =>
    typeof reason === "string" && reason.length > 0 && reason.length <= 256));
  return value;
}
export function detail(paged, id, api) {
  let status, completion, outcome, dropCounts, previous = -1n;
  const events = [], windowEvidence = [];
  for (const doc of paged) {
    need(doc[api ? "recordingId" : "recording_id"] === id && ["complete", "partial", "invalid", "unavailable"].includes(doc.completion));
    const drops = doc[api ? "dropCountsByPriority" : "drop_counts_by_priority"];
    need(drops && typeof drops === "object" && !Array.isArray(drops) && Object.keys(drops).length <= 256);
    need(Object.entries(drops).every(([priority, count]) => /^\d{1,10}$/.test(priority) &&
      typeof count === "string" && /^\d{1,20}$/.test(count)));
    if (completion === undefined) {
      status = lifecycleStatus(doc.status); completion = doc.completion; outcome = doc.outcome; dropCounts = drops;
    }
    need(doc.status === status && isDeepStrictEqual(drops, dropCounts));
    windowEvidence.push({ first: doc.events[0]?.sequence ?? null, last: doc.events.at(-1)?.sequence ?? null,
      count: doc.events.length, reasons: reasonList(doc[api ? "incompleteEvidence" : "incomplete_evidence"]) });
    need(doc.completion === completion && Object.hasOwn(doc, "outcome") && isDeepStrictEqual(doc.outcome, outcome));
    for (const raw of doc.events) {
      need(typeof raw.sequence === "string" && /^[0-9]{1,20}$/.test(raw.sequence) && BigInt(raw.sequence) > previous);
      previous = BigInt(raw.sequence);
      const event = { sequence: raw.sequence };
      for (const field of ["kind", "symbol", "interaction", "exception", "gap"]) {
        need(Object.hasOwn(raw, field)); event[field] = raw[field];
      }
      need(typeof raw.kind === "string");
      for (const [camel, snake] of [["eventId", "event_id"], ["parentEventId", "parent_event_id"],
        ["asyncParentEventId", "async_parent_event_id"], ["frameId", "frame_id"], ["sourceBinding", "source_binding"]]) {
        need(Object.hasOwn(raw, api ? camel : snake)); event[camel] = raw[api ? camel : snake];
      }
      events.push(event);
    }
  }
  return { status, completion, outcome, dropCounts, events, windowEvidence };
}
export function equal(left, right) { need(isDeepStrictEqual(left, right)); }

export function inventory(paged, projectId, api) {
  const rows = new Map();
  let after = null;
  for (const doc of paged) {
    need(doc[api ? "projectId" : "project_id"] === projectId && doc.after === after && doc.limit === 20);
    for (const value of doc.recordings) {
      const read = (camel, snake) => value[api ? camel : snake];
      const id = recordingId(read("recordingId", "recording_id"));
      const count = read("eventCount", "event_count"), segments = read("segmentCount", "segment_count");
      const first = read("firstSequence", "first_sequence"), last = read("lastSequence", "last_sequence");
      need(!rows.has(id) && typeof count === "string" && /^[1-9][0-9]{0,3}$/.test(count) && Number(count) <= 4000);
      need(typeof segments === "string" && /^[1-9][0-9]{0,3}$/.test(segments) && Number(segments) <= Number(count));
      need(typeof first === "string" && typeof last === "string" && /^\d{1,20}$/.test(first) && /^\d{1,20}$/.test(last));
      need(BigInt(first) <= BigInt(last));
      need(["complete", "partial", "invalid", "unavailable"].includes(value.completion));
      rows.set(id, { count: Number(count), segments: Number(segments), first, last,
        status: lifecycleStatus(value.status), completion: value.completion,
        incompleteEvidence: reasonList(read("incompleteEvidence", "incomplete_evidence")) });
    }
    after = doc[api ? "nextAfter" : "next_after"];
    if (after !== null) need(after === doc.recordings.at(-1)?.[api ? "recordingId" : "recording_id"]);
  }
  return rows;
}

export function verifiedDetail(paged, id, projectId, row, api) {
  const result = detail(paged, id, api);
  let cursor = null;
  for (const doc of paged) {
    const read = (camel, snake) => doc[api ? camel : snake];
    need(read("projectId", "project_id") === projectId && doc.limit === 100 && doc.cursor === cursor);
    need(read("segmentCount", "segment_count") === String(row.segments));
    need(read("firstSequence", "first_sequence") === (doc.events[0]?.sequence ?? null));
    need(read("lastSequence", "last_sequence") === (doc.events.at(-1)?.sequence ?? null));
    cursor = read("nextCursor", "next_cursor");
  }
  need(result.status === row.status && result.completion === row.completion && result.events.length === row.count);
  need(result.events[0].sequence === row.first && result.events.at(-1).sequence === row.last);
  return { ...result, listEvidence: row.incompleteEvidence };
}

export function missingParents(events) {
  const ids = new Set(events.map(event => event.eventId).filter(id => id !== null));
  // The Node adapter records causal links between events of the same request.
  return {
    direct: events.filter(event => event.parentEventId !== null && !ids.has(event.parentEventId)).length,
    async: events.filter(event => event.asyncParentEventId !== null && !ids.has(event.asyncParentEventId)).length,
  };
}

function completeCapture(row) {
  return row.status === "complete" && row.completion === "complete" && row.listEvidence.length === 0 &&
    row.windowEvidence.every(window => window.reasons.length === 0) && Object.values(row.dropCounts).every(count => BigInt(count) === 0n) &&
    row.events.every(event => event.kind !== "recording_event_kind:gap" && event.gap === null);
}

// The admitted CLI/viewer inventory is a private input to storage inspection.
// Later capture semantics or viewer shutdown can fail independently.
export function judgeObservedWorkload({ save, projectId, cliRows, readyIds, details, config, report }) {
  save("store-inventory.private.json", JSON.stringify({ projectId: recordingId(projectId), recordings: [...cliRows] }));
  const ids = [...cliRows.keys()];
  report.cliViewerParity = true;
  need(readyIds.every(id => completeCapture(details.get(id))));
  const statuses = {};
  for (const id of ids.filter(id => !readyIds.includes(id))) {
    const row = details.get(id); report.workloadRecordings++;
    if (completeCapture(row)) report.complete++;
    const entries = row.events.filter(event => event.kind === "recording_event_kind:frame_enter");
    const roots = entries.filter(event => event.symbol === "node:http.Server.request");
    if (roots.length === 1 && roots[0].eventId !== null && roots[0].parentEventId === null) report.httpRoots++;
    if (entries.some(event => (event.symbol || "").startsWith("express.handler:"))) report.expressHandlers++;
    const missing = missingParents(row.events);
    report.orphanParents += missing.direct;
    report.orphanAsyncParents += missing.async;
    if (row.outcome?.kind !== "responded" || !Number.isInteger(row.outcome?.httpStatus)) report.absentOutcome++;
    else statuses[row.outcome.httpStatus] = (statuses[row.outcome.httpStatus] || 0) + 1;
  }
  report.aggregateResponseCountMatches = report.workloadRecordings === config.responses;
  report.aggregateResponseStatusMultisetMatches = isDeepStrictEqual(statuses, config.statuses);
  need(report.aggregateResponseStatusMultisetMatches);
  need(report.workloadRecordings > 0 && report.complete === report.workloadRecordings && report.httpRoots === report.workloadRecordings &&
    report.expressHandlers > 0 && report.absentOutcome === 0 && report.orphanParents === 0 && report.orphanAsyncParents === 0 && report.aggregateResponseCountMatches);
}
