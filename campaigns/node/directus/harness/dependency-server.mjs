// Deterministic local dependency for the Directus outbound scenarios (runs in a container on the
// harness network, alias `dep`). Serves fixed bytes / fixed failures and records every request.
import http from "node:http";

// 1x1 transparent PNG (fixed bytes)
const PNG = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==", "base64");
const log = [];

http
  .createServer((req, res) => {
    const url = new URL(req.url, "http://dep");
    if (url.pathname === "/__requests") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(log));
      return;
    }
    log.push({ method: req.method, path: url.pathname });
    if (url.pathname === "/fixtures/synthetic.png") {
      res.writeHead(200, { "content-type": "image/png", "content-length": PNG.length });
      res.end(PNG);
    } else if (url.pathname === "/fixtures/unavailable.png") {
      res.writeHead(503, { "content-type": "text/plain", "retry-after": "1" });
      res.end("synthetic dependency outage");
    } else {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
    }
  })
  .listen(8080, "0.0.0.0", () => console.log("dependency server listening on 8080"));
