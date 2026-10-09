import { BUILTIN_MODULES } from "./manifest.cjs";
import { installHttpCapture } from "./http-capture.cjs";
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
