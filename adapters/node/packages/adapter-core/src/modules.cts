import { BUILTIN_MODULES } from "./manifest.cjs";
import { installHttpCapture } from "./http-capture.cjs";
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

export function expressModule(resolve: (specifier: string) => string = defaultResolve): InstrumentationModule {
  return {
    descriptor: descriptor("express"),
    detect(environment) {
      const node = supportedNode(environment);
      if (!node.supported) return node;
      try {
        resolve("express/package.json");
        return { supported: true };
      } catch {
        return { supported: false, reason: "express_not_found" };
      }
    },
    install() { registerRouteResolver(resolveExpressRoute); },
  };
}

function defaultResolve(specifier: string): string {
  const paths = [process.cwd(), ...(require.main?.paths ?? [])];
  return require.resolve(specifier, { paths });
}
