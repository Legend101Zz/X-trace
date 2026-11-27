import { BUILTIN_MODULES } from "./manifest.cjs";
import { installHttpCapture } from "./http-capture.cjs";
import { installExpressLayerPatch } from "./express-instrument.cjs";
import { installFastifyPatch, resolveFastifyRoute } from "./fastify-instrument.cjs";
import { installNestPatch } from "./nest-instrument.cjs";
import { installHttpClientCapture, installMysqlCapture, installPgCapture } from "./interactions/index.cjs";
import { installProcessLinkageCapture } from "./process-linkage.cjs";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve as resolvePath } from "node:path";
import { registerRouteResolver } from "./runtime/context.cjs";
import type { HttpCaptureTransport } from "./runtime/transport.cjs";
import type { InstallEnvironment, InstrumentationModule, ModuleDescriptor, DetectResult } from "./runtime/registry.cjs";

function descriptor(name: string): ModuleDescriptor {
  const found = BUILTIN_MODULES.find((module) => module.name === name);
  if (!found) throw new Error("module descriptor missing");
  return found;
}

function supportedNode(environment: InstallEnvironment): DetectResult {
  const major = Number.parseInt(environment.nodeVersion.replace(/^v/, ""), 10);
  return major >= 22 && major < 25 ? { supported: true } : { supported: false, reason: "node_runtime_unsupported" };
}

/** HTTP/HTTPS request root at Server.prototype.emit('request'). */
export function nodeHttpModule(transport: () => HttpCaptureTransport): InstrumentationModule {
  return {
    descriptor: descriptor("node-http"),
    detect: supportedNode,
    install() { installHttpCapture(transport()); },
  };
}

/** AsyncLocalStorage correlation is part of Node itself; installing the HTTP root provides it. */
export function asyncContextModule(): InstrumentationModule {
  return {
    descriptor: descriptor("async-context"),
    detect: supportedNode,
    install() { /* contexts are created by the HTTP root */ },
  };
}

/**
 * Express 4 and 5 route template: the matched `req.route.path` once the response finished.
 * Only a literal string path on an unmounted app/router qualifies; regex or array paths and
 * mounted routers (whose base URL holds concrete values) stay unresolved, never guessed.
 */
export function resolveExpressRoute(request: unknown): string {
  const candidate = request as { route?: { path?: unknown }; baseUrl?: unknown } | undefined;
  const path = candidate?.route?.path;
  if (typeof path !== "string" || !path.startsWith("/") || path.length > 1024) return "";
  const base = candidate?.baseUrl;
  if (typeof base === "string" && base !== "") return "";
  return path;
}

export function expressModule(
  resolve: (specifier: string) => string = resolveFromEntry,
  transport?: () => HttpCaptureTransport,
): InstrumentationModule {
  return {
    descriptor: descriptor("express"),
    detect(environment) {
      const node = supportedNode(environment);
      if (!node.supported) return node;
      let located: string;
      let fromMedusa = false;
      try {
        located = resolve("express/package.json");
      } catch (error) {
        if (!(error instanceof Error) || !("code" in error) || error.code !== "MODULE_NOT_FOUND") {
          return { supported: false, reason: "express_not_found" };
        }
        try {
          located = resolveMedusaExpress(resolve);
          fromMedusa = true;
        } catch {
          return { supported: false, reason: "express_not_found" };
        }
      }
      const major = expressMajor(located, fromMedusa);
      return major === 4 || major === 5 || (!fromMedusa && major === 0)
        ? { supported: true }
        : { supported: false, reason: "express_version_unsupported" };
    },
    install() {
      // Finish-time resolution stays as the fallback for shapes the Layer patch does not recognize.
      registerRouteResolver(resolveExpressRoute);
      if (transport) installExpressLayerPatch({ transport });
    },
  };
}

/** Resolve Express as Medusa itself does, without loading either package or altering Node's search paths. */
export function resolveMedusaExpress(resolve: (specifier: string) => string = resolveFromEntry): string {
  return createRequire(resolve("@medusajs/medusa")).resolve("express/package.json");
}

/** A dependency-scope fallback must identify a real supported Express package. */
function expressMajor(packageJsonPath: string, requireName: boolean): number {
  try {
    const parsed = JSON.parse(readFileSync(packageJsonPath, "utf8")) as { name?: unknown; version?: unknown };
    if (typeof parsed.version !== "string") return 0;
    if (requireName && (parsed.name !== "express" || !/^(?:4|5)\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)*$/.test(parsed.version))) return 0;
    return Number.parseInt(parsed.version, 10) || 0;
  } catch {
    return 0;
  }
}

export function resolveFromEntry(specifier: string): string {
  // Preloads run before the entry module exists, so `require.main` is unset: the entry script's own
  // directory (argv[1]) is where an application's node_modules is found when cwd is elsewhere.
  const entry = process.argv[1];
  const paths = [process.cwd(), ...(typeof entry === "string" && entry !== "" ? [dirname(resolvePath(entry))] : []), ...(require.main?.paths ?? [])];
  return require.resolve(specifier, { paths });
}

function readPackageMajor(packageJsonPath: string, expectedName: string): { readable: boolean; nameMatch: boolean; major: number } {
  try {
    const parsed = JSON.parse(readFileSync(packageJsonPath, "utf8")) as { name?: unknown; version?: unknown };
    const nameMatch = parsed.name === expectedName;
    const major = typeof parsed.version === "string" ? Number.parseInt(parsed.version, 10) || 0 : 0;
    return { readable: true, nameMatch, major };
  } catch {
    return { readable: false, nameMatch: false, major: 0 };
  }
}

export function fastifyModule(
  resolve: (specifier: string) => string = resolveFromEntry,
  transport?: () => HttpCaptureTransport,
): InstrumentationModule {
  return {
    descriptor: descriptor("fastify"),
    detect(environment) {
      const node = supportedNode(environment);
      if (!node.supported) return node;
      let located: string;
      try {
        located = resolve("fastify/package.json");
      } catch {
        return { supported: false, reason: "fastify_not_found" };
      }
      const pkg = readPackageMajor(located, "fastify");
      if (pkg.readable && (!pkg.nameMatch || (pkg.major !== 4 && pkg.major !== 5))) {
        return { supported: false, reason: "fastify_version_unsupported" };
      }
      return { supported: true };
    },
    install() {
      registerRouteResolver(resolveFastifyRoute);
      if (transport) installFastifyPatch({ transport });
    },
  };
}

export function nestModule(
  resolve: (specifier: string) => string = resolveFromEntry,
  transport?: () => HttpCaptureTransport,
): InstrumentationModule {
  return {
    descriptor: descriptor("nest"),
    detect(environment) {
      const node = supportedNode(environment);
      if (!node.supported) return node;
      let located: string;
      try {
        located = resolve("@nestjs/core/package.json");
      } catch {
        return { supported: false, reason: "nest_not_found" };
      }
      const pkg = readPackageMajor(located, "@nestjs/core");
      if (pkg.readable && (!pkg.nameMatch || pkg.major < 8 || pkg.major > 11)) {
        return { supported: false, reason: "nest_version_unsupported" };
      }
      return { supported: true };
    },
    install() {
      if (transport) installNestPatch({ transport });
    },
  };
}

export function pgModule(
  resolve: (specifier: string) => string = resolveFromEntry,
  transport?: () => HttpCaptureTransport,
): InstrumentationModule {
  return {
    descriptor: descriptor("pg"),
    detect(environment) {
      const node = supportedNode(environment);
      if (!node.supported) return node;
      let located: string;
      try {
        located = resolve("pg/package.json");
      } catch {
        return { supported: false, reason: "pg_not_found" };
      }
      const pkg = readPackageMajor(located, "pg");
      if (pkg.readable && (!pkg.nameMatch || pkg.major !== 8)) {
        return { supported: false, reason: "pg_version_unsupported" };
      }
      return { supported: true };
    },
    install() {
      if (transport) installPgCapture({ transport });
    },
  };
}

export function mysqlModule(
  resolve: (specifier: string) => string = resolveFromEntry,
  transport?: () => HttpCaptureTransport,
): InstrumentationModule {
  return {
    descriptor: descriptor("mysql"),
    detect(environment) {
      const node = supportedNode(environment);
      if (!node.supported) return node;
      const candidates: Array<{ spec: string; name: string; supportedMajors: number[] }> = [
        { spec: "mysql2/package.json", name: "mysql2", supportedMajors: [2, 3] },
        { spec: "mysql/package.json", name: "mysql", supportedMajors: [2] },
      ];
      let sawUnsupported = false;
      for (const candidate of candidates) {
        try {
          const located = resolve(candidate.spec);
          const pkg = readPackageMajor(located, candidate.name);
          if (!pkg.readable || (pkg.nameMatch && candidate.supportedMajors.includes(pkg.major))) {
            return { supported: true };
          }
          sawUnsupported = true;
        } catch { /* try next */ }
      }
      return { supported: false, reason: sawUnsupported ? "mysql_version_unsupported" : "mysql_not_found" };
    },
    install() {
      if (transport) installMysqlCapture({ transport });
    },
  };
}

export function outboundHttpModule(transport?: () => HttpCaptureTransport): InstrumentationModule {
  return {
    descriptor: descriptor("outbound-http"),
    detect: supportedNode,
    install() {
      if (transport) installHttpClientCapture({ transport });
    },
  };
}

export function processLinkageModule(transport?: () => HttpCaptureTransport): InstrumentationModule {
  return {
    descriptor: descriptor("process-linkage"),
    detect: supportedNode,
    install() {
      if (transport) installProcessLinkageCapture({ transport });
    },
  };
}
