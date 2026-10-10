import { BUILTIN_MODULES } from "./manifest.cjs";
import { installHttpCapture } from "./http-capture.cjs";
import { installExpressLayerPatch } from "./express-instrument.cjs";
import { readFileSync } from "node:fs";
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
  resolve: (specifier: string) => string = defaultResolve,
  transport?: () => HttpCaptureTransport,
): InstrumentationModule {
  return {
    descriptor: descriptor("express"),
    detect(environment) {
      const node = supportedNode(environment);
      if (!node.supported) return node;
      let located: string;
      try {
        located = resolve("express/package.json");
      } catch {
        return { supported: false, reason: "express_not_found" };
      }
      const major = expressMajor(located);
      return major !== 0 && major !== 4 && major !== 5 ? { supported: false, reason: "express_version_unsupported" } : { supported: true };
    },
    install() {
      // Finish-time resolution stays as the fallback for shapes the Layer patch does not recognize.
      registerRouteResolver(resolveExpressRoute);
      if (transport) installExpressLayerPatch({ transport });
    },
  };
}

/** Major version of the resolved express package, or 0 when it cannot be read (then not gated here). */
function expressMajor(packageJsonPath: string): number {
  try {
    const parsed = JSON.parse(readFileSync(packageJsonPath, "utf8")) as { version?: unknown };
    return typeof parsed.version === "string" ? Number.parseInt(parsed.version, 10) || 0 : 0;
  } catch {
    return 0;
  }
}

function defaultResolve(specifier: string): string {
  // Preloads run before the entry module exists, so `require.main` is unset: the entry script's own
  // directory (argv[1]) is where an application's node_modules is found when cwd is elsewhere.
  const entry = process.argv[1];
  const paths = [process.cwd(), ...(typeof entry === "string" && entry !== "" ? [dirname(resolvePath(entry))] : []), ...(require.main?.paths ?? [])];
  return require.resolve(specifier, { paths });
}
