import type { ModuleDescriptor } from "./runtime/registry.cjs";

/** Single source of truth for what this adapter can provide; the dist manifest is generated from it. */

export const RUNTIME_RANGE = "node >=22 <25";

/** Built-in modules shipped in this dist. Dependency modules (express, pg, ...) append here. */
export const BUILTIN_MODULES: readonly ModuleDescriptor[] = [
  {
    name: "node-http",
    capability: "http.server.request_root",
    limitationsWhenAbsent: ["http_root_unavailable", "http_status_unavailable"],
  },
  {
    name: "async-context",
    capability: "async_correlation",
    limitationsWhenAbsent: ["async_correlation_unavailable"],
  },
];

/** Limitations that hold regardless of which modules install in this version. */
export const BASELINE_LIMITATIONS: readonly string[] = [
  "async_handler_completion_unobserved",
  "database_and_outbound_calls_unavailable",
  "frameworks_uninstrumented",
  "http2_unsupported",
  "route_unavailable",
  "source_locations_unavailable",
  "values_unavailable",
];

export interface CapabilityManifest {
  schema: 2;
  name: "xtrace-node";
  runtime: string;
  capabilities: string[];
  limitations: string[];
  modules: Array<{ name: string; capability: string; limitationsWhenAbsent: string[] }>;
}

/** Deterministic: same modules in, byte-identical manifest out (it is hashed into the dist). */
export function buildManifest(
  modules: readonly ModuleDescriptor[] = BUILTIN_MODULES,
  baseline: readonly string[] = BASELINE_LIMITATIONS,
): CapabilityManifest {
  const sorted = [...modules].sort((left, right) => left.name.localeCompare(right.name));
  return {
    schema: 2,
    name: "xtrace-node",
    runtime: RUNTIME_RANGE,
    capabilities: [...new Set(sorted.map((module) => module.capability))].sort(),
    limitations: [...new Set(baseline)].sort(),
    modules: sorted.map((module) => ({
      name: module.name,
      capability: module.capability,
      limitationsWhenAbsent: [...module.limitationsWhenAbsent].sort(),
    })),
  };
}

/** Limitations that hold for a run: the baseline plus those of every module that did not install. */
export function effectiveLimitations(
  installed: ReadonlySet<string>,
  modules: readonly ModuleDescriptor[] = BUILTIN_MODULES,
  baseline: readonly string[] = BASELINE_LIMITATIONS,
): string[] {
  const codes = new Set(baseline);
  for (const module of modules) {
    if (installed.has(module.name)) continue;
    for (const limitation of module.limitationsWhenAbsent) codes.add(limitation);
  }
  return [...codes].sort();
}
