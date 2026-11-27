import type { ExceptionFacts, InteractionFacts } from "../runtime/events.cjs";

/** Bounds aligned with daemon ingest validation (`crates/xtrace-ingest/src/event_rules.rs`). */
export const MAX_LABEL_BYTES = 128;
export const MAX_HOST_BYTES = 253;
export const MAX_SUMMARY_BYTES = 512;

const CONTROL_CHARS = /[\x00-\x1f\x7f]/g;
const QUOTES_AND_BACKTICKS = /['"`]/g;
const PEM_BLOCK = /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)/gi;
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b/g;
const AWS_KEY_PATTERN = /\bAKIA[0-9A-Z]{16}\b/g;
const AUTH_SCHEME_PATTERN = /\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{6,}/gi;
const URL_USERINFO_PATTERN = /([a-z][a-z0-9+.-]*:\/\/)[^\s/@?#]+@/gi;
const SECRET_KV_PATTERN =
  /\b(password|passwd|pwd|passphrase|secret|token|api[_-]?key|authorization|credential|private[_-]?key|access[_-]?key|cookie|session|signature)\s*([:=])\s*(?:'[^']*'|"[^"]*"|`[^`]*`|[^\s,;)]+)/gi;

const SAFE_ERROR_NAME = /^[A-Za-z_][A-Za-z0-9_.]{0,63}$/;
const SAFE_ERROR_CODE = /^(?:[A-Z][A-Z0-9_]{1,31}|[0-9]{5})$/;
const SECRET_NAME_WORDS = [
  "password", "passwd", "pwd", "passphrase", "secret", "token", "apikey",
  "authorization", "credential", "privatekey", "cookie", "session", "bearer",
  "accesskey", "signature",
];

/** Truncates `value` so its UTF-8 encoding never exceeds `maxBytes` and never splits surrogate pairs. */
export function truncateUtf8(value: string, maxBytes: number): string {
  if (maxBytes <= 0 || value === "") return "";
  if (Buffer.byteLength(value, "utf8") <= maxBytes) return value;
  const ellipsis = maxBytes > 3 ? "..." : "";
  const limit = maxBytes - ellipsis.length;
  let end = 0;
  let bytes = 0;
  for (const ch of value) {
    const size = Buffer.byteLength(ch, "utf8");
    if (bytes + size > limit) break;
    bytes += size;
    end += ch.length;
  }
  return value.slice(0, end) + ellipsis;
}

export function stripControlChars(value: string, replacement = " "): string {
  return value.replace(CONTROL_CHARS, replacement);
}

/** Scrubs secret-shaped substrings (JWTs, AWS keys, PEM blocks, Bearer/Basic headers, URL userinfo, secret key=val). */
export function scrubSecretText(value: string): string {
  return value
    .replace(PEM_BLOCK, "[redacted]")
    .replace(JWT_PATTERN, "[redacted]")
    .replace(AWS_KEY_PATTERN, "[redacted]")
    .replace(AUTH_SCHEME_PATTERN, "$1 [redacted]")
    .replace(URL_USERINFO_PATTERN, "$1")
    .replace(SECRET_KV_PATTERN, "$1$2[redacted]");
}

/** Strips userinfo, ports, query/fragment delimiters, quotes, control chars and secret patterns from a host string. */
export function sanitizeHost(rawHost: unknown): string {
  if (typeof rawHost !== "string") return "";
  let host = stripControlChars(rawHost, "").trim();
  if (host === "") return "";
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(host)) {
    try {
      host = new URL(host).hostname;
    } catch {
      host = host.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
    }
  }
  const atIndex = host.lastIndexOf("@");
  if (atIndex >= 0) host = host.slice(atIndex + 1);
  const cut = host.search(/[/?#]/);
  if (cut >= 0) host = host.slice(0, cut);
  if (host.startsWith("[")) {
    const close = host.indexOf("]");
    host = close > 1 ? host.slice(1, close) : host.replace(/[\[\]]/g, "");
  } else {
    const firstColon = host.indexOf(":");
    if (firstColon >= 0 && host.indexOf(":", firstColon + 1) === -1) {
      host = host.slice(0, firstColon);
    }
  }
  host = scrubSecretText(host)
    .replace(/[@?#]/g, "")
    .replace(QUOTES_AND_BACKTICKS, "")
    .replace(/\s+/g, "")
    .toLowerCase();
  if (host === "" || host.includes("[redacted]")) return "";
  return truncateUtf8(host, MAX_HOST_BYTES);
}

export function sanitizePort(rawPort: unknown): number | undefined {
  const num = typeof rawPort === "number" ? rawPort
    : typeof rawPort === "string" && /^\d+$/.test(rawPort.trim()) ? Number.parseInt(rawPort.trim(), 10)
      : Number.NaN;
  return Number.isInteger(num) && num >= 1 && num <= 65535 ? num : undefined;
}

export function sanitizeStatusCode(rawStatus: unknown): number | undefined {
  return typeof rawStatus === "number" && Number.isInteger(rawStatus) && rawStatus >= 100 && rawStatus <= 599
    ? rawStatus
    : undefined;
}

/** Sanitizes a label/identifier (`driver`, `method`, `schema`, `table`) within 128 UTF-8 bytes without quotes/control chars. */
export function sanitizeIdentifier(raw: unknown): string {
  if (typeof raw !== "string") return "";
  const cleaned = scrubSecretText(stripControlChars(raw, ""))
    .replace(QUOTES_AND_BACKTICKS, "")
    .replace(/[@?#\s]/g, "");
  if (cleaned === "" || cleaned === "[redacted]") return "";
  return truncateUtf8(cleaned, MAX_LABEL_BYTES);
}

export function sanitizeMethod(raw: unknown, fallback = "query", caseMode: "upper" | "lower" | "keep" = "keep"): string {
  const cleaned = sanitizeIdentifier(raw);
  const value = cleaned === "" ? fallback : cleaned;
  const cased = caseMode === "upper" ? value.toUpperCase() : caseMode === "lower" ? value.toLowerCase() : value;
  return truncateUtf8(cased, MAX_LABEL_BYTES);
}

export interface SanitizedSqlResult {
  summary: string;
  statementKind: "select" | "insert" | "update" | "delete" | "ddl" | "call" | "other";
  schema: string;
  table: string;
}

/**
 * Normalizes and redacts a SQL statement into a literal-free, quote-free, parameter-free shape.
 * Also extracts best-effort `statementKind`, `schema`, and `table` without retaining literals.
 */
export function sanitizeSql(rawSql: unknown): SanitizedSqlResult {
  const raw = typeof rawSql === "string"
    ? rawSql
    : rawSql !== null && typeof rawSql === "object"
      ? typeof (rawSql as { text?: unknown }).text === "string"
        ? (rawSql as { text: string }).text
        : typeof (rawSql as { sql?: unknown }).sql === "string"
          ? (rawSql as { sql: string }).sql
          : ""
      : "";
  if (raw.trim() === "") return { summary: "", statementKind: "other", schema: "", table: "" };

  const withoutComments = raw
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/--[^\r\n]*/g, " ");

  const kind = detectStatementKind(withoutComments);

  // Strip SQL literals ($tag$...$tag$, '...', X'...', B'...', 0x..., and non-identifier "...")
  // BEFORE extracting schema/table so literal contents can never match as a table/schema name.
  const withoutLiterals = stripControlChars(withoutComments, " ")
    .replace(/\$([A-Za-z0-9_]*)\$[\s\S]*?\$\1\$/g, " ? ")
    .replace(/\b(?:X|B)'[^']*'/gi, " ? ")
    .replace(/\b0x[0-9a-fA-F]+\b/g, " ? ")
    .replace(/'(?:[^'\\]|\\.|'')*'/g, " ? ")
    .replace(/(\b(?:FROM|JOIN|INTO|UPDATE|TABLE|EXISTS|CALL|EXEC|EXECUTE)\s+|(?:\.)\s*)"([A-Za-z_][A-Za-z0-9_$]*)"/gi, "$1$2")
    .replace(/"(?:[^"\\]|\\.|"")*"/g, " ? ");

  const target = extractSqlTarget(withoutLiterals);

  // Replace remaining credential clauses, parameter placeholders, and numeric literals.
  let sanitized = withoutLiterals
    .replace(/\b(PASSWORD|IDENTIFIED\s+BY|SECRET|TOKEN|PASSPHRASE)\s*(?:=\s*|\s+)([^\s,;)]+)/gi, "$1 ?")
    .replace(/\$\d+/g, "?")
    .replace(/(^|[\s(,=])[:@][A-Za-z_][A-Za-z0-9_]*/g, "$1?")
    .replace(/(?<![A-Za-z0-9_.$])\d+(?:\.\d+)?\b/g, "?");

  sanitized = scrubSecretText(sanitized)
    .replace(QUOTES_AND_BACKTICKS, "")
    .replace(/\s+/g, " ")
    .trim();

  return {
    summary: truncateUtf8(sanitized, MAX_SUMMARY_BYTES),
    statementKind: kind,
    schema: target.schema,
    table: target.table,
  };
}

function detectStatementKind(sql: string): SanitizedSqlResult["statementKind"] {
  const trimmed = sql.trimStart();
  const match = /^([A-Za-z]+)/.exec(trimmed);
  if (!match) return "other";
  const keyword = match[1]!.toLowerCase();
  if (keyword === "select" || keyword === "with") return "select";
  if (keyword === "insert" || keyword === "replace") return "insert";
  if (keyword === "update") return "update";
  if (keyword === "delete") return "delete";
  if (keyword === "create" || keyword === "alter" || keyword === "drop" || keyword === "truncate") return "ddl";
  if (keyword === "call" || keyword === "exec" || keyword === "execute") return "call";
  return "other";
}

function extractSqlTarget(sql: string): { schema: string; table: string } {
  const ident = `(?:["\`]?([A-Za-z_][A-Za-z0-9_$]*)["\`]?\\.)?["\`]?([A-Za-z_][A-Za-z0-9_$]*)["\`]?`;
  const patterns = [
    new RegExp(`\\bFROM\\s+${ident}`, "i"),
    new RegExp(`\\bINTO\\s+${ident}`, "i"),
    new RegExp(`\\bUPDATE\\s+${ident}`, "i"),
    new RegExp(`\\b(?:CREATE|ALTER|DROP|TRUNCATE)\\s+(?:TABLE|VIEW|INDEX)\\s+(?:IF\\s+(?:NOT\\s+)?EXISTS\\s+)?${ident}`, "i"),
    new RegExp(`\\b(?:CALL|EXEC|EXECUTE)\\s+${ident}`, "i"),
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(sql);
    if (!match) continue;
    const schema = sanitizeIdentifier(match[1] ?? "");
    const table = sanitizeIdentifier(match[2] ?? "");
    if (table) return { schema, table };
  }
  return { schema: "", table: "" };
}

/** Extracts `host`, `port`, and `schema` (database) from a connection string without ever retaining user/password/query. */
export function extractConnectionTarget(connectionString: unknown): { host: string; port?: number; schema: string } {
  if (typeof connectionString !== "string" || connectionString.trim() === "") return { host: "", schema: "" };
  try {
    const parsed = new URL(connectionString);
    const host = sanitizeHost(parsed.hostname);
    const port = sanitizePort(parsed.port);
    const dbName = parsed.pathname.replace(/^\/+/, "").split("/")[0] ?? "";
    const schema = sanitizeIdentifier(dbName);
    return { host, ...(port !== undefined ? { port } : {}), schema };
  } catch {
    return { host: "", schema: "" };
  }
}

export interface SanitizedHttpTarget {
  method: string;
  host: string;
  port?: number;
  summary: string;
}

/** Sanitizes an outbound HTTP target: method + host + port + pathname only (never query strings, fragments, headers, or auth). */
export function sanitizeHttpTarget(
  rawUrlOrPath: unknown,
  options: { method?: unknown; host?: unknown; hostname?: unknown; port?: unknown; path?: unknown; pathname?: unknown; protocol?: unknown } = {},
  defaultProtocol = "http:",
): SanitizedHttpTarget {
  const method = sanitizeMethod(options.method, "GET", "upper");
  let parsed: URL | undefined;
  let hasAuthority = false;
  if (rawUrlOrPath instanceof URL) {
    parsed = rawUrlOrPath;
    hasAuthority = true;
  } else if (typeof rawUrlOrPath === "string" && rawUrlOrPath.trim() !== "") {
    try {
      if (rawUrlOrPath.startsWith("/")) {
        parsed = new URL(rawUrlOrPath, `${defaultProtocol}//localhost`);
      } else {
        parsed = new URL(rawUrlOrPath);
        hasAuthority = true;
      }
    } catch {
      parsed = undefined;
    }
  }

  let rawHost = options.hostname ?? options.host ?? (parsed && hasAuthority ? parsed.hostname : "");
  let rawPort = options.port ?? (parsed && hasAuthority && parsed.port !== "" ? parsed.port : undefined);
  if (rawPort === undefined && typeof options.host === "string" && options.hostname === undefined) {
    const colon = options.host.lastIndexOf(":");
    if (colon > 0 && !options.host.includes("]")) {
      rawPort = options.host.slice(colon + 1);
    }
  }
  const host = sanitizeHost(rawHost);
  const port = sanitizePort(rawPort);

  let rawPath = typeof options.pathname === "string" ? options.pathname
    : typeof options.path === "string" ? options.path
      : parsed ? parsed.pathname
        : "/";
  // Strip query strings and fragments before scrubbing so query parameter values are never observed.
  const queryOrFrag = rawPath.search(/[?#]/);
  if (queryOrFrag >= 0) rawPath = rawPath.slice(0, queryOrFrag);
  rawPath = stripControlChars(rawPath, "");
  rawPath = scrubSecretText(rawPath).replace(QUOTES_AND_BACKTICKS, "").replace(/[?#]/g, "");
  if (!rawPath.startsWith("/")) rawPath = `/${rawPath}`;
  const summary = truncateUtf8(`${method} ${rawPath}`, MAX_SUMMARY_BYTES);
  return {
    method,
    host,
    ...(port !== undefined ? { port } : {}),
    summary,
  };
}

/** Rebuilds an `InteractionFacts` object with ONLY permitted bounded fields, never extra keys or secrets. */
export function sanitizeInteractionFacts(input: InteractionFacts): InteractionFacts {
  const driver = sanitizeIdentifier(input.driver) || "unknown";
  const method = sanitizeMethod(input.method, "unknown", input.kind === "outbound-http" ? "upper" : "keep");
  const summary = truncateUtf8(
    scrubSecretText(stripControlChars(input.summary ?? "", " "))
      .replace(QUOTES_AND_BACKTICKS, "")
      .replace(/\s+/g, " ")
      .trim(),
    MAX_SUMMARY_BYTES,
  );
  const schema = sanitizeIdentifier(input.schema);
  const table = sanitizeIdentifier(input.table);
  const host = sanitizeHost(input.host);
  const port = sanitizePort(input.port);
  const statusCode = sanitizeStatusCode(input.statusCode);

  return {
    kind: input.kind,
    driver,
    method,
    summary,
    ...(schema !== "" ? { schema } : {}),
    ...(table !== "" ? { table } : {}),
    ...(host !== "" ? { host } : {}),
    ...(port !== undefined ? { port } : {}),
    ...(statusCode !== undefined ? { statusCode } : {}),
  };
}

/** Never emits raw exception messages or stacks: safe constructor type plus optional machine error code only. */
export function safeExceptionFacts(error: unknown): ExceptionFacts {
  if (!(error instanceof Error)) return { type: "UnknownError", message: "" };
  const candidate = typeof error.name === "string" && error.name !== "" ? error.name : error.constructor?.name ?? "Error";
  const normalized = candidate.replace(/[^A-Za-z0-9_.]/g, "").toLowerCase();
  const hasSecretWord = SECRET_NAME_WORDS.some((word) => normalized.includes(word));
  const type = SAFE_ERROR_NAME.test(candidate) && !hasSecretWord ? candidate : "Error";
  const rawCode = (error as { code?: unknown }).code;
  const message = typeof rawCode === "string" && SAFE_ERROR_CODE.test(rawCode) ? rawCode : "";
  return { type, message };
}
