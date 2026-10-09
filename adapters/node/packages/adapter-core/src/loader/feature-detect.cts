/** Chooses how Node source can be observed on this process, from facts only (NG-06). */

export type LoaderStrategy = "register-hooks" | "compile-wrapper";

export interface LoaderFacts {
  nodeVersion: string;
  hasRegisterHooks: boolean;
  /** `process.execArgv` of the application process. */
  execArgv: readonly string[];
  /** The application's own NODE_OPTIONS (before the launcher added anything). */
  nodeOptions: string;
}

export interface LoaderPlan {
  strategy: LoaderStrategy;
  /** Stable limitation codes that hold for this process; empty when nothing is lost. */
  limitations: string[];
}

const ASYNC_LOADER_FLAG = /^--(?:import|loader|experimental-loader)(?:=|$)/;

/**
 * Conformance finding (Node 22.23.0, 2026-10-09): `module.registerHooks` combined with an
 * application loader registered through `module.register` at startup (`--import tsx`,
 * `--loader ts-node/esm`) aborts the process with `this[#customizations].loadSync is not a
 * function` when our hook was registered before the loader. Node 24.21.0 does not. On Node 22
 * with any async loader flag present we therefore never call registerHooks; CommonJS is
 * observed through `Module.prototype._compile` and ESM source stays untransformed.
 */
export function chooseLoaderStrategy(facts: LoaderFacts): LoaderPlan {
  const major = Number.parseInt(facts.nodeVersion.replace(/^v/, ""), 10);
  if (!facts.hasRegisterHooks) {
    return { strategy: "compile-wrapper", limitations: ["esm_source_transform_unavailable", "register_hooks_unavailable"] };
  }
  if (major < 24 && hasAsyncLoaderFlag(facts)) {
    return { strategy: "compile-wrapper", limitations: ["esm_source_transform_unavailable", "loader_conflict_node22"] };
  }
  return { strategy: "register-hooks", limitations: [] };
}

function hasAsyncLoaderFlag(facts: LoaderFacts): boolean {
  if (facts.execArgv.some((arg) => ASYNC_LOADER_FLAG.test(arg))) return true;
  return facts.nodeOptions.split(/\s+/).some((arg) => ASYNC_LOADER_FLAG.test(arg));
}
