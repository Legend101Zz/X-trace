// Invoked with docker exec inside the positively identified app container.
// The destination is a constant. Cookies, requests and responses never enter argv.
import { ordinaryRequest } from "./installed-ordinary-scope.mjs";
import { requireFact } from "./installed-readback.mjs";

try {
  requireFact(process.argv.length === 2, "ordinary_request_arguments");
  let input = "";
  for await (const bytes of process.stdin) {
    requireFact(Buffer.byteLength(input) + bytes.length <= 65536, "ordinary_request_bound");
    input += bytes.toString("utf8");
  }
  const { method, route, headers = {}, body, readiness } = JSON.parse(input);
  const ping = readiness === true && method === "GET" && route === "/server/ping" && body === undefined;
  requireFact(ping || (readiness === undefined && ordinaryRequest(method, route)), "ordinary_request_not_allowed");
  requireFact(Object.keys(headers).every(key => ["content-type", "authorization"].includes(key))
    && (body === undefined || typeof body === "string"), "ordinary_request_shape");
  const result = await fetch("http://127.0.0.1:8055" + route, { method, headers, body,
    redirect: "error", signal: AbortSignal.timeout(ping ? 3000 : 20000) });
  const chunks = [];
  let length = 0;
  if (result.body) for await (const chunk of result.body) {
    length += chunk.length;
    requireFact(length <= 1024 * 1024, "ordinary_response_bound");
    chunks.push(chunk);
  }
  process.stdout.write(JSON.stringify({ status: result.status, text: Buffer.concat(chunks).toString("utf8") }));
} catch { process.exitCode = 1; }
