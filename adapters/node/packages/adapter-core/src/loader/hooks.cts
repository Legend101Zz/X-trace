import nodeModule = require("node:module");
import { fileURLToPath } from "node:url";
import { chooseLoaderStrategy, type LoaderPlan } from "./feature-detect.cjs";

const INSTALLED = Symbol.for("xtrace.loader.v1");

export type SourceFormat = "commonjs" | "module";

export interface TransformContext {
  /** Absolute filesystem path of the source file. */
  filename: string;
  format: SourceFormat;
}

/** Returns replacement source, or undefined to leave the module untouched. May throw. */
export type SourceTransform = (source: string, context: TransformContext) => string | undefined;

export interface LoaderInstall extends LoaderPlan {
  /** Count of transform exceptions swallowed so far (module still loaded from its original source). */
  failures(): number;
}

type LoadContext = nodeModule.LoadHookContext;
type LoadResult = nodeModule.LoadFnOutput;
type ModuleWithHooks = { registerHooks?: typeof nodeModule.registerHooks };
type CompilePrototype = { _compile: (this: unknown, content: string, filename: string, ...rest: unknown[]) => unknown };

/**
 * Installs one idempotent source observer for this process. A throwing transform can never
 * break loading: the module is served from its original source and the failure is counted.
 */
export function installSourceTransform(transform: SourceTransform, plan?: LoaderPlan): LoaderInstall {
  const holder = globalThis as unknown as Record<symbol, LoaderInstall | undefined>;
  const existing = holder[INSTALLED];
  if (existing) return existing;

  const chosen = plan ?? chooseLoaderStrategy({
    nodeVersion: process.version,
    hasRegisterHooks: typeof (nodeModule as ModuleWithHooks).registerHooks === "function",
    execArgv: process.execArgv,
    nodeOptions: process.env.XTRACE_NODE_ORIGINAL_OPTIONS ?? process.env.NODE_OPTIONS ?? "",
  });
  let failures = 0;
  const safeTransform = (source: string, context: TransformContext): string | undefined => {
    try {
      return transform(source, context);
    } catch {
      failures += 1;
      return undefined;
    }
  };

  if (chosen.strategy === "register-hooks") {
    (nodeModule as ModuleWithHooks).registerHooks!({
      load(url, context, next) {
        const result = next(url, context);
        try {
          const format = effectiveFormat(url, context, result);
          if (!format || result.source == null) return result;
          const replaced = safeTransform(typeof result.source === "string" ? result.source : new TextDecoder().decode(result.source), { filename: fileURLToPath(url), format });
          return replaced === undefined ? result : { ...result, source: replaced };
        } catch {
          failures += 1;
          return result;
        }
      },
    });
  } else {
    const proto = (nodeModule as unknown as { prototype: CompilePrototype }).prototype;
    const original = proto._compile;
    proto._compile = function xtraceCompile(this: unknown, content: string, filename: string, ...rest: unknown[]): unknown {
      const replaced = typeof content === "string" && isUserSource(filename)
        ? safeTransform(content, { filename, format: "commonjs" })
        : undefined;
      return Reflect.apply(original, this, [replaced ?? content, filename, ...rest]);
    };
  }

  const install: LoaderInstall = { ...chosen, failures: () => failures };
  Object.defineProperty(holder, INSTALLED, { value: install, enumerable: false });
  return install;
}

function effectiveFormat(url: string, context: LoadContext, result: LoadResult): SourceFormat | undefined {
  if (!url.startsWith("file:")) return undefined;
  const format = result.format ?? context.format;
  if (format === "commonjs" || format === "module") return format;
  // A require() of a `.js` file in a package without "type" reports no format; the loader
  // then treats it as CommonJS, so only the require condition makes that safe to claim.
  if (format == null && context.conditions.includes("require") && url.endsWith(".js")) return "commonjs";
  return undefined;
}

function isUserSource(filename: string): boolean {
  return filename.startsWith("/") || /^[A-Za-z]:[\\/]/.test(filename);
}
