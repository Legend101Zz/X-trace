/** Instrumentation module contract (03c 4.4): detect, install, never half-patch. */

export interface ModuleDescriptor {
  /** Stable module name, e.g. `node-http`, `express`. */
  name: string;
  /** Capability reported to the daemon when (and only when) the module installed. */
  capability: string;
  /** Limitation codes that stay true while the module is absent or disabled. */
  limitationsWhenAbsent: readonly string[];
}

export type DetectResult = { supported: true } | { supported: false; reason: string };

export interface InstallEnvironment {
  nodeVersion: string;
  /** Resolved package version for dependency modules; empty for built-ins. */
  packageVersion: string;
}

export interface InstrumentationModule {
  readonly descriptor: ModuleDescriptor;
  detect(environment: InstallEnvironment): DetectResult;
  install(environment: InstallEnvironment): void;
}

export interface ModuleStatus {
  name: string;
  state: "installed" | "disabled";
  /** Present for disabled modules: a stable code, never an exception message. */
  code?: string;
}

/** Tracks which modules actually installed; a failing module disables only itself. */
export class ModuleRegistry {
  readonly #modules = new Map<string, ModuleStatus>();
  readonly #descriptors = new Map<string, ModuleDescriptor>();

  tryInstall(module: InstrumentationModule, environment: InstallEnvironment): ModuleStatus {
    const { name } = module.descriptor;
    this.#descriptors.set(name, module.descriptor);
    let status: ModuleStatus;
    try {
      const detected = module.detect(environment);
      if (!detected.supported) {
        status = { name, state: "disabled", code: detected.reason };
      } else {
        module.install(environment);
        status = { name, state: "installed" };
      }
    } catch {
      status = { name, state: "disabled", code: "module_install_failed" };
    }
    this.#modules.set(name, status);
    return status;
  }

  statuses(): ModuleStatus[] {
    return [...this.#modules.values()];
  }

  capabilities(): string[] {
    return this.statuses()
      .filter((status) => status.state === "installed")
      .map((status) => this.#descriptors.get(status.name)!.capability)
      .sort();
  }

  /** Limitations that currently hold: every disabled module's, plus its failure code. */
  limitations(): string[] {
    const codes = new Set<string>();
    for (const status of this.statuses()) {
      if (status.state === "installed") continue;
      for (const limitation of this.#descriptors.get(status.name)!.limitationsWhenAbsent) codes.add(limitation);
      if (status.code) codes.add(status.code);
    }
    return [...codes].sort();
  }
}
