// Static route analysis for Express, Fastify and Nest.
//
// The analyzer only parses source text with the TypeScript compiler API. It never imports, requires,
// evaluates or runs the code it reads and starts no process. Output is the JSON-lines contract in
// schema/fixtures/static-claim-contract.json.
import * as fs from "node:fs";
import * as path from "node:path";
import ts from "typescript-parser";

export const FRAMEWORKS = ["express", "fastify", "nest"] as const;
export type Framework = (typeof FRAMEWORKS)[number];

export interface AnalyzeOptions {
  root: string;
  framework: Framework;
  maxFiles?: number;
  maxFileBytes?: number;
}

const NAME = "xtrace-node-static";
const VERSION = "0.0.1";
const RULESETS: Record<Framework, string> = {
  express: "express-routes/1",
  fastify: "fastify-routes/1",
  nest: "nest-decorators/1",
};

type Basis = "literal" | "concatenated" | "computed";
const BASIS_RANK: Record<Basis, number> = { literal: 0, concatenated: 1, computed: 2 };

function weakest(a: Basis, b: Basis): Basis {
  return BASIS_RANK[b] > BASIS_RANK[a] ? b : a;
}

interface PathValue {
  text: string;
  basis: Basis;
  unresolved: boolean;
}

const EMPTY_PATH: PathValue = { text: "", basis: "literal", unresolved: false };

interface Evidence {
  path: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

interface RouteDecl {
  scope: string;
  methods: string[];
  unconstrained: boolean;
  path: PathValue;
  handler: string | undefined;
  evidence: Evidence;
}

interface Mount {
  parent: string;
  child: string;
  prefix: PathValue;
}

type ScopeKind = "app" | "router" | "plugin" | "unknown";

interface Imported {
  spec: string;
  imported: string;
}

interface FileInfo {
  rel: string;
  abs: string;
  sf: ts.SourceFile;
  imports: Map<string, Imported>;
  consts: Map<string, ts.Expression>;
  varScopes: Map<string, ScopeKind>;
  fns: Map<string, string>;
  fileDefault: string | undefined;
  usesFramework: boolean;
}

const SKIPPED_DIRECTORIES = new Set([
  ".git",
  ".next",
  ".nuxt",
  ".turbo",
  "build",
  "coverage",
  "dist",
  "node_modules",
  "out",
]);
const SOURCE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts"];
const ROUTE_METHODS = new Set(["get", "post", "put", "delete", "patch", "head", "options", "all"]);
const UNCONSTRAINED = ["GET", "POST", "PUT", "PATCH", "DELETE"];
const RECEIVER_NAMES = new Set([
  "app",
  "router",
  "fastify",
  "server",
  "instance",
  "api",
  "routes",
  "routing",
]);
const MAX_CHAINS_PER_ROUTE = 16;
const MAX_MOUNT_DEPTH = 8;

function placeholder(name: string): string {
  return "{" + (/^[A-Za-z0-9_.-]+$/.test(name) ? name : "unresolved") + "}";
}

class Analysis {
  readonly files = new Map<string, FileInfo>();
  readonly routes: RouteDecl[] = [];
  readonly mounts: Mount[] = [];
  readonly scopeKinds = new Map<string, ScopeKind>();
  readonly incomplete = new Set<string>();
  readonly diagnostics: string[] = [];
  filesScanned = 0;

  constructor(
    readonly root: string,
    readonly framework: Framework,
  ) {}

  // ---------------------------------------------------------------- loading

  load(maxFiles: number, maxFileBytes: number): void {
    const found: string[] = [];
    const walk = (dir: string): void => {
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        this.diagnostics.push(diagnostic("file_unreadable", this.relative(dir)));
        this.incomplete.add("file_unreadable");
        return;
      }
      entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isSymbolicLink()) continue;
        if (entry.isDirectory()) {
          if (!SKIPPED_DIRECTORIES.has(entry.name)) walk(full);
        } else if (
          entry.isFile() &&
          SOURCE_EXTENSIONS.some((ext) => entry.name.endsWith(ext)) &&
          !entry.name.endsWith(".d.ts")
        ) {
          if (found.length >= maxFiles) this.incomplete.add("budget_exceeded");
          else found.push(full);
        }
      }
    };
    walk(this.root);

    for (const abs of found) {
      const rel = this.relative(abs);
      try {
        if (fs.statSync(abs).size > maxFileBytes) {
          this.diagnostics.push(diagnostic("file_too_large", rel));
          this.incomplete.add("budget_exceeded");
          continue;
        }
        const text = fs.readFileSync(abs, "utf8");
        const sf = ts.createSourceFile(abs, text, ts.ScriptTarget.ES2022, true);
        this.filesScanned++;
        const parseDiagnostics = (sf as unknown as { parseDiagnostics?: unknown[] }).parseDiagnostics;
        if (parseDiagnostics !== undefined && parseDiagnostics.length > 0) {
          this.diagnostics.push(diagnostic("parse_error", rel));
          this.incomplete.add("parse_error");
          continue;
        }
        this.files.set(abs, this.index({ rel, abs, sf }));
      } catch {
        this.diagnostics.push(diagnostic("file_unreadable", rel));
        this.incomplete.add("file_unreadable");
      }
    }
    // Export maps need every file indexed first.
    for (const file of this.files.values()) this.indexExports(file);
  }

  relative(abs: string): string {
    return path.relative(this.root, abs).split(path.sep).join("/");
  }

  private index(base: { rel: string; abs: string; sf: ts.SourceFile }): FileInfo {
    const file: FileInfo = {
      ...base,
      imports: new Map(),
      consts: new Map(),
      varScopes: new Map(),
      fns: new Map(),
      fileDefault: undefined,
      usesFramework: false,
    };
    const frameworkSpecs =
      this.framework === "express" ? ["express"] : this.framework === "fastify" ? ["fastify", "@fastify/"] : [];
    const noteSpec = (spec: string): void => {
      if (frameworkSpecs.some((s) => spec === s || spec.startsWith(s.endsWith("/") ? s : s + "/") || spec === s.replace(/\/$/, ""))) {
        file.usesFramework = true;
      }
    };
    for (const statement of file.sf.statements) {
      if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
        const spec = statement.moduleSpecifier.text;
        noteSpec(spec);
        const clause = statement.importClause;
        if (clause?.name !== undefined) file.imports.set(clause.name.text, { spec, imported: "default" });
        const bindings = clause?.namedBindings;
        if (bindings !== undefined && ts.isNamespaceImport(bindings)) {
          file.imports.set(bindings.name.text, { spec, imported: "*" });
        } else if (bindings !== undefined && ts.isNamedImports(bindings)) {
          for (const element of bindings.elements) {
            file.imports.set(element.name.text, {
              spec,
              imported: (element.propertyName ?? element.name).text,
            });
          }
        }
      }
      if (ts.isFunctionDeclaration(statement) && statement.name !== undefined) {
        file.fns.set(statement.name.text, fnKey(file.rel, statement));
      }
      if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          this.indexTopLevelDeclaration(file, declaration, noteSpec);
        }
      }
    }
    // Constructors may sit inside functions (`function createApp() { const app = express(); ... }`).
    const visit = (node: ts.Node): void => {
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer !== undefined) {
        const kind = constructorKind(node.initializer);
        if (kind !== undefined) file.varScopes.set(node.name.text, kind);
      }
      if (ts.isCallExpression(node) && isRequire(node)) {
        const arg = node.arguments[0];
        if (arg !== undefined && ts.isStringLiteralLike(arg)) noteSpec(arg.text);
      }
      ts.forEachChild(node, visit);
    };
    visit(file.sf);
    return file;
  }

  private indexTopLevelDeclaration(
    file: FileInfo,
    declaration: ts.VariableDeclaration,
    noteSpec: (spec: string) => void,
  ): void {
    const init = declaration.initializer;
    if (init === undefined) return;
    const unwrapped = unwrap(init);
    const required = requireTarget(unwrapped);
    if (required !== undefined) {
      noteSpec(required.spec);
      if (ts.isIdentifier(declaration.name)) {
        file.imports.set(declaration.name.text, { spec: required.spec, imported: required.property ?? "default" });
      } else if (ts.isObjectBindingPattern(declaration.name)) {
        for (const element of declaration.name.elements) {
          if (ts.isIdentifier(element.name)) {
            const imported = element.propertyName !== undefined && ts.isIdentifier(element.propertyName)
              ? element.propertyName.text
              : element.name.text;
            file.imports.set(element.name.text, { spec: required.spec, imported });
          }
        }
      }
      return;
    }
    if (!ts.isIdentifier(declaration.name)) return;
    if (ts.isArrowFunction(unwrapped) || ts.isFunctionExpression(unwrapped)) {
      file.fns.set(declaration.name.text, fnKey(file.rel, unwrapped));
    } else if (constructorKind(unwrapped) === undefined) {
      file.consts.set(declaration.name.text, unwrapped);
    }
  }

  private indexExports(file: FileInfo): void {
    for (const statement of file.sf.statements) {
      if (ts.isFunctionDeclaration(statement) && hasDefaultModifier(statement)) {
        file.fileDefault = fnKey(file.rel, statement);
      } else if (ts.isExportAssignment(statement) && !statement.isExportEquals) {
        file.fileDefault = this.refFromLocal(file, statement.expression) ?? file.fileDefault;
      } else if (
        ts.isExpressionStatement(statement) &&
        ts.isBinaryExpression(statement.expression) &&
        statement.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        statement.expression.left.getText(file.sf) === "module.exports"
      ) {
        file.fileDefault = this.refFromLocal(file, statement.expression.right) ?? file.fileDefault;
      }
    }
  }

  // ------------------------------------------------------------ resolution

  /** Scope key for an expression that names a scope in `file` (no cross-file hop). */
  private refFromLocal(file: FileInfo, expression: ts.Expression): string | undefined {
    const expr = unwrap(expression);
    if (ts.isIdentifier(expr)) {
      if (file.varScopes.has(expr.text)) return `${file.rel}::${expr.text}`;
      const local = file.fns.get(expr.text);
      if (local !== undefined) return local;
      return undefined;
    }
    if (ts.isArrowFunction(expr) || ts.isFunctionExpression(expr)) return fnKey(file.rel, expr);
    if (ts.isCallExpression(expr)) {
      const kind = constructorKind(expr);
      if (kind !== undefined) return undefined;
    }
    return undefined;
  }

  resolveSpec(from: FileInfo, spec: string): FileInfo | undefined {
    if (!spec.startsWith(".")) return undefined;
    const base = path.resolve(path.dirname(from.abs), spec);
    const stems = [base, base.replace(/\.(m|c)?jsx?$/, "")];
    for (const stem of stems) {
      for (const candidate of [stem, ...SOURCE_EXTENSIONS.map((e) => stem + e), ...SOURCE_EXTENSIONS.map((e) => path.join(stem, "index" + e))]) {
        const hit = this.files.get(candidate);
        if (hit !== undefined) return hit;
      }
    }
    return undefined;
  }

  /** Scope key that `expression` (used in `file`) refers to, following one import hop. */
  resolveScopeRef(file: FileInfo, expression: ts.Expression): string | undefined {
    const expr = unwrap(expression);
    const local = this.refFromLocal(file, expr);
    if (local !== undefined) return local;
    if (ts.isIdentifier(expr)) {
      const imported = file.imports.get(expr.text);
      if (imported === undefined) return undefined;
      return this.importedScope(file, imported);
    }
    const required = requireTarget(expr);
    if (required !== undefined) return this.importedScope(file, { spec: required.spec, imported: required.property ?? "default" });
    return undefined;
  }

  private importedScope(file: FileInfo, imported: Imported): string | undefined {
    const target = this.resolveSpec(file, imported.spec);
    if (target === undefined) return undefined;
    if (imported.imported === "default" || imported.imported === "*") return target.fileDefault;
    if (target.varScopes.has(imported.imported)) return `${target.rel}::${imported.imported}`;
    return target.fns.get(imported.imported);
  }

  // ------------------------------------------------------ path expressions

  evalPath(file: FileInfo, expression: ts.Expression, depth = 0): PathValue {
    const expr = unwrap(expression);
    if (ts.isStringLiteralLike(expr)) return { text: expr.text, basis: "literal", unresolved: false };
    if (ts.isBinaryExpression(expr) && expr.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      return this.combine(this.evalPath(file, expr.left, depth), this.evalPath(file, expr.right, depth));
    }
    if (ts.isTemplateExpression(expr)) {
      let value: PathValue = { text: expr.head.text, basis: "literal", unresolved: false };
      for (const span of expr.templateSpans) {
        value = this.combine(value, this.evalPath(file, span.expression, depth));
        value = this.combine(value, { text: span.literal.text, basis: "literal", unresolved: false });
      }
      return value;
    }
    if (ts.isIdentifier(expr)) return this.constant(file, expr.text, depth);
    const name = ts.isPropertyAccessExpression(expr) ? expr.name.text : "unresolved";
    return { text: placeholder(name), basis: "computed", unresolved: true };
  }

  private combine(left: PathValue, right: PathValue): PathValue {
    if (left.unresolved || right.unresolved) {
      return { text: left.text + right.text, basis: "computed", unresolved: true };
    }
    const basis: Basis = left.text === "" ? right.basis : right.text === "" ? left.basis : "concatenated";
    return { text: left.text + right.text, basis, unresolved: false };
  }

  private constant(file: FileInfo, name: string, depth: number): PathValue {
    const unresolved: PathValue = { text: placeholder(name), basis: "computed", unresolved: true };
    if (depth > 6) return unresolved;
    const own = file.consts.get(name);
    if (own !== undefined) {
      const value = this.evalPath(file, own, depth + 1);
      return value.unresolved ? unresolved : { ...value, basis: weakest(value.basis, "concatenated") };
    }
    const imported = file.imports.get(name);
    if (imported !== undefined) {
      const target = this.resolveSpec(file, imported.spec);
      const expression = target?.consts.get(imported.imported === "default" ? name : imported.imported);
      if (target !== undefined && expression !== undefined) {
        const value = this.evalPath(target, expression, depth + 1);
        return value.unresolved ? unresolved : { ...value, basis: weakest(value.basis, "concatenated") };
      }
    }
    return unresolved;
  }

  /** Path argument that may be one string-like expression or an array of them. */
  evalPathList(file: FileInfo, expression: ts.Expression): PathValue[] {
    const expr = unwrap(expression);
    if (ts.isArrayLiteralExpression(expr)) {
      return expr.elements.map((element) => this.evalPath(file, element));
    }
    return [this.evalPath(file, expr)];
  }

  // -------------------------------------------------- Express and Fastify

  collectRoutes(): void {
    for (const file of this.files.values()) {
      const visit = (node: ts.Node): void => {
        if (ts.isCallExpression(node)) this.inspectCall(file, node);
        ts.forEachChild(node, visit);
      };
      visit(file.sf);
    }
  }

  private evidence(file: FileInfo, start: ts.Node, end: ts.Node): Evidence {
    const a = file.sf.getLineAndCharacterOfPosition(start.getStart(file.sf));
    const b = file.sf.getLineAndCharacterOfPosition(end.getEnd());
    return {
      path: file.rel,
      startLine: a.line + 1,
      startColumn: a.character + 1,
      endLine: b.line + 1,
      endColumn: Math.max(b.character + 1, b.line === a.line ? a.character + 2 : 1),
    };
  }

  private receiverScope(file: FileInfo, receiver: ts.Expression, at: ts.Node): string | undefined {
    const expr = unwrap(receiver);
    let name: string | undefined;
    if (ts.isIdentifier(expr)) name = expr.text;
    else if (ts.isPropertyAccessExpression(expr)) name = expr.name.text;
    if (name === undefined) return undefined;
    // 1. a function whose first parameter is the receiver is a plugin scope
    for (let parent: ts.Node | undefined = at.parent; parent !== undefined; parent = parent.parent) {
      if (ts.isFunctionLike(parent) && "parameters" in parent) {
        const first = (parent as ts.FunctionLikeDeclaration).parameters[0];
        if (first !== undefined && ts.isIdentifier(first.name) && first.name.text === name && RECEIVER_NAMES.has(name)) {
          const key = fnKey(file.rel, parent as ts.FunctionLikeDeclaration);
          if (!this.scopeKinds.has(key)) this.scopeKinds.set(key, "plugin");
          return key;
        }
      }
    }
    // 2. a variable created by express() / Router() / fastify()
    const kind = file.varScopes.get(name);
    if (kind !== undefined) {
      const key = `${file.rel}::${name}`;
      this.scopeKinds.set(key, kind);
      return key;
    }
    // 3. a conventional receiver name in a file that imports the framework
    if (RECEIVER_NAMES.has(name) && file.usesFramework) {
      const key = `${file.rel}::${name}`;
      if (!this.scopeKinds.has(key)) this.scopeKinds.set(key, name === "router" || name === "routes" ? "router" : "unknown");
      return key;
    }
    return undefined;
  }

  private inspectCall(file: FileInfo, call: ts.CallExpression): void {
    const callee = call.expression;
    if (!ts.isPropertyAccessExpression(callee)) return;
    const member = callee.name.text;
    const args = call.arguments;

    if (this.framework === "express" && member === "use") {
      this.inspectMount(file, call, callee.expression, args, false);
      return;
    }
    if (this.framework === "fastify" && member === "register") {
      this.inspectMount(file, call, callee.expression, args, true);
      return;
    }
    if (this.framework === "fastify" && member === "route") {
      this.inspectFastifyRoute(file, call, callee.expression);
      return;
    }
    if (!ROUTE_METHODS.has(member)) return;

    // router.route('/x').get(h).post(h): unwrap the chain to the .route(path) call.
    let base: ts.Expression = callee.expression;
    let chained: ts.CallExpression | undefined;
    for (;;) {
      const inner = unwrap(base);
      if (ts.isCallExpression(inner) && ts.isPropertyAccessExpression(inner.expression)) {
        const innerMember = inner.expression.name.text;
        if (innerMember === "route" && this.framework === "express") {
          chained = inner;
          break;
        }
        if (ROUTE_METHODS.has(innerMember)) {
          base = inner.expression.expression;
          continue;
        }
      }
      break;
    }
    if (chained !== undefined && ts.isPropertyAccessExpression(chained.expression)) {
      const scope = this.receiverScope(file, chained.expression.expression, chained);
      const pathArg = chained.arguments[0];
      if (scope === undefined || pathArg === undefined) return;
      this.addRoute(file, scope, member, this.evalPathList(file, pathArg), call.arguments[call.arguments.length - 1], call, pathArg);
      return;
    }
    const pathArg = args[0];
    if (pathArg === undefined || args.length < 2) return;
    const scope = this.receiverScope(file, callee.expression, call);
    if (scope === undefined) return;
    this.addRoute(file, scope, member, this.evalPathList(file, pathArg), args[args.length - 1], call, pathArg);
  }

  private addRoute(
    file: FileInfo,
    scope: string,
    member: string,
    paths: PathValue[],
    handlerArg: ts.Expression | undefined,
    start: ts.Node,
    end: ts.Node,
  ): void {
    const unconstrained = member === "all";
    const methods = unconstrained ? UNCONSTRAINED : [member.toUpperCase()];
    const handler = handlerName(file, handlerArg);
    for (const value of paths) {
      this.routes.push({ scope, methods, unconstrained, path: value, handler, evidence: this.evidence(file, start, end) });
    }
  }

  private inspectFastifyRoute(file: FileInfo, call: ts.CallExpression, receiver: ts.Expression): void {
    const options = call.arguments[0];
    if (options === undefined || !ts.isObjectLiteralExpression(options)) return;
    const scope = this.receiverScope(file, receiver, call);
    if (scope === undefined) return;
    let methods: string[] = [];
    let urls: PathValue[] = [];
    let handler: string | undefined;
    for (const property of options.properties) {
      if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) continue;
      const key = property.name.getText(file.sf);
      if (ts.isShorthandPropertyAssignment(property)) {
        if (key === "handler") handler = property.name.text;
        continue;
      }
      if (key === "method") {
        const value = unwrap(property.initializer);
        const elements = ts.isArrayLiteralExpression(value) ? [...value.elements] : [value];
        methods = elements.filter(ts.isStringLiteralLike).map((e) => e.text.toUpperCase());
      } else if (key === "url" || key === "path") {
        urls = this.evalPathList(file, property.initializer);
      } else if (key === "handler") {
        handler = handlerName(file, property.initializer);
      }
    }
    if (methods.length === 0 || urls.length === 0) return;
    for (const url of urls) {
      this.routes.push({
        scope,
        methods,
        unconstrained: false,
        path: url,
        handler,
        evidence: this.evidence(file, call, options),
      });
    }
  }

  private inspectMount(
    file: FileInfo,
    call: ts.CallExpression,
    receiver: ts.Expression,
    args: ts.NodeArray<ts.Expression>,
    fastify: boolean,
  ): void {
    const parent = this.receiverScope(file, receiver, call);
    if (parent === undefined) return;
    if (fastify) {
      const target = args[0];
      if (target === undefined) return;
      const child = this.resolveScopeRef(file, target);
      if (child === undefined) {
        this.diagnostics.push(diagnostic("unsupported_syntax", file.rel));
        return;
      }
      let prefix = EMPTY_PATH;
      const options = args[1];
      if (options !== undefined && ts.isObjectLiteralExpression(options)) {
        for (const property of options.properties) {
          if (ts.isPropertyAssignment(property) && property.name.getText(file.sf) === "prefix") {
            prefix = this.evalPath(file, property.initializer);
          }
        }
      }
      this.mounts.push({ parent, child, prefix });
      return;
    }
    let prefix = EMPTY_PATH;
    let rest: readonly ts.Expression[] = args;
    const first = args[0];
    if (first !== undefined && (ts.isStringLiteralLike(unwrap(first)) || ts.isArrayLiteralExpression(unwrap(first)) || ts.isTemplateExpression(unwrap(first)))) {
      prefix = this.evalPathList(file, first)[0] ?? EMPTY_PATH;
      rest = args.slice(1);
    }
    for (const arg of rest) {
      const child = this.resolveScopeRef(file, arg);
      if (child !== undefined) this.mounts.push({ parent, child, prefix });
    }
  }

  /** Mount prefixes from the outermost application down to `scope`; one list per mount path. */
  private chains(scope: string, depth: number): { parts: PathValue[]; unmounted: boolean }[] {
    const incoming = this.mounts.filter((m) => m.child === scope);
    if (incoming.length === 0 || depth >= MAX_MOUNT_DEPTH) {
      const kind = this.scopeKinds.get(scope) ?? "unknown";
      return [{ parts: [], unmounted: kind === "router" || kind === "plugin" }];
    }
    const out: { parts: PathValue[]; unmounted: boolean }[] = [];
    for (const mount of incoming) {
      for (const parent of this.chains(mount.parent, depth + 1)) {
        out.push({ parts: [...parent.parts, mount.prefix], unmounted: parent.unmounted });
      }
    }
    return out;
  }

  claimLines(): string[] {
    const lines: string[] = [];
    for (const route of this.routes) {
      let chains = this.chains(route.scope, 0);
      if (chains.length > MAX_CHAINS_PER_ROUTE) {
        chains = chains.slice(0, MAX_CHAINS_PER_ROUTE);
        this.incomplete.add("budget_exceeded");
      }
      for (const chain of chains) {
        const prefixes = chain.parts.filter((part) => part.text !== "" || part.unresolved);
        let basis: Basis = route.path.basis;
        let unresolved = route.path.unresolved;
        for (const part of prefixes) {
          basis = weakest(basis, part.basis);
          unresolved = unresolved || part.unresolved;
        }
        if (prefixes.length > 0) basis = weakest(basis, "concatenated");
        const limitations = new Set<string>();
        if (unresolved) limitations.add("route_constant_unresolved");
        if (chain.unmounted) limitations.add("mount_unresolved");
        if (route.unconstrained) limitations.add("mapping_method_unconstrained");
        for (const method of route.methods) {
          lines.push(
            claimLine(method, [...prefixes.map((p) => p.text), route.path.text], basis, route.handler, [...limitations].sort(), route.evidence),
          );
        }
      }
    }
    return lines;
  }

  // ------------------------------------------------------------------ Nest

  private nestGlobalPrefixes: PathValue[] = [];

  collectNestPrefixes(): void {
    for (const file of this.files.values()) {
      const visit = (node: ts.Node): void => {
        if (ts.isCallExpression(node)) this.inspectNestGlobalPrefix(file, node);
        ts.forEachChild(node, visit);
      };
      visit(file.sf);
    }
  }

  private inspectNestGlobalPrefix(file: FileInfo, call: ts.CallExpression): void {
    if (ts.isPropertyAccessExpression(call.expression) && call.expression.name.text === "setGlobalPrefix") {
      const arg = call.arguments[0];
      if (arg !== undefined) this.nestGlobalPrefixes.push(this.evalPath(file, arg));
    }
  }

  nestClaimLines(): string[] {
    const lines: string[] = [];
    const prefixes = new Set(this.nestGlobalPrefixes.map((p) => p.text));
    const global = this.nestGlobalPrefixes[0];
    const globalOk = global !== undefined && prefixes.size === 1;
    for (const file of this.files.values()) {
      const visit = (node: ts.Node): void => {
        if (ts.isClassDeclaration(node)) this.nestClass(file, node, globalOk ? global : undefined, global !== undefined && !globalOk, lines);
        ts.forEachChild(node, visit);
      };
      visit(file.sf);
    }
    return lines;
  }

  private nestClass(
    file: FileInfo,
    node: ts.ClassDeclaration,
    global: PathValue | undefined,
    ambiguousGlobal: boolean,
    lines: string[],
  ): void {
    const controller = decoratorCall(node, "Controller");
    if (controller === undefined) return;
    const className = node.name?.text ?? "anonymous";
    let prefixes: PathValue[] = [EMPTY_PATH];
    const arg = controller.args[0];
    if (arg !== undefined) {
      const expr = unwrap(arg);
      if (ts.isObjectLiteralExpression(expr)) {
        for (const property of expr.properties) {
          if (ts.isPropertyAssignment(property) && property.name.getText(file.sf) === "path") {
            prefixes = this.evalPathList(file, property.initializer);
          }
        }
      } else {
        prefixes = this.evalPathList(file, expr);
      }
    }
    for (const member of node.members) {
      if (!ts.isMethodDeclaration(member) || member.name === undefined) continue;
      for (const [decoratorName, verb] of NEST_VERBS) {
        const decorator = decoratorCall(member, decoratorName);
        if (decorator === undefined) continue;
        const methodArg = decorator.args[0];
        const paths = methodArg === undefined ? [EMPTY_PATH] : this.evalPathList(file, methodArg);
        const unconstrained = verb === "ALL";
        const methods = unconstrained ? UNCONSTRAINED : [verb];
        const handler = `${className}#${member.name.getText(file.sf)}`;
        for (const prefix of prefixes) {
          for (const methodPath of paths) {
            let basis = weakest(prefix.basis, methodPath.basis);
            const parts: string[] = [];
            if (global !== undefined) {
              parts.push(global.text);
              basis = weakest(basis, weakest(global.basis, "concatenated"));
            }
            parts.push(prefix.text, methodPath.text);
            const limitations = new Set<string>();
            if (prefix.unresolved || methodPath.unresolved || global?.unresolved === true) limitations.add("route_constant_unresolved");
            if (ambiguousGlobal) limitations.add("mount_unresolved");
            if (unconstrained) limitations.add("mapping_method_unconstrained");
            for (const method of methods) {
              lines.push(claimLine(method, parts, basis, safeHandler(handler), [...limitations].sort(), this.evidence(file, decorator.node, decorator.node)));
            }
          }
        }
      }
    }
  }
}

const NEST_VERBS: [string, string][] = [
  ["Get", "GET"],
  ["Post", "POST"],
  ["Put", "PUT"],
  ["Delete", "DELETE"],
  ["Patch", "PATCH"],
  ["Head", "HEAD"],
  ["Options", "OPTIONS"],
  ["All", "ALL"],
];

function decoratorCall(
  node: ts.Node,
  name: string,
): { node: ts.Decorator; args: readonly ts.Expression[] } | undefined {
  if (!ts.canHaveDecorators(node)) return undefined;
  for (const decorator of ts.getDecorators(node) ?? []) {
    const expr = decorator.expression;
    if (ts.isCallExpression(expr) && ts.isIdentifier(expr.expression) && expr.expression.text === name) {
      return { node: decorator, args: expr.arguments };
    }
    if (ts.isIdentifier(expr) && expr.text === name) return { node: decorator, args: [] };
  }
  return undefined;
}

function unwrap(expression: ts.Expression): ts.Expression {
  let current = expression;
  for (;;) {
    if (ts.isParenthesizedExpression(current)) current = current.expression;
    else if (ts.isAsExpression(current) || ts.isSatisfiesExpression(current)) current = current.expression;
    else if (ts.isNonNullExpression(current)) current = current.expression;
    else if (ts.isAwaitExpression(current)) current = current.expression;
    else return current;
  }
}

function isRequire(call: ts.CallExpression): boolean {
  return ts.isIdentifier(call.expression) && call.expression.text === "require";
}

/** `require('x')` or `require('x').name`, as a module reference. */
function requireTarget(expr: ts.Expression): { spec: string; property: string | undefined } | undefined {
  if (ts.isCallExpression(expr) && isRequire(expr)) {
    const arg = expr.arguments[0];
    if (arg !== undefined && ts.isStringLiteralLike(arg)) return { spec: arg.text, property: undefined };
  }
  if (ts.isPropertyAccessExpression(expr)) {
    const inner = unwrap(expr.expression);
    if (ts.isCallExpression(inner) && isRequire(inner)) {
      const arg = inner.arguments[0];
      if (arg !== undefined && ts.isStringLiteralLike(arg)) return { spec: arg.text, property: expr.name.text };
    }
  }
  return undefined;
}

function constructorKind(expression: ts.Expression): ScopeKind | undefined {
  const expr = unwrap(expression);
  if (!ts.isCallExpression(expr)) return undefined;
  const callee = expr.expression;
  if (ts.isIdentifier(callee)) {
    if (callee.text === "express" || callee.text === "fastify" || callee.text === "Fastify") return "app";
    if (callee.text === "Router") return "router";
  }
  if (ts.isPropertyAccessExpression(callee) && callee.name.text === "Router") return "router";
  if (ts.isCallExpression(callee) && isRequire(callee)) {
    const arg = callee.arguments[0];
    if (arg !== undefined && ts.isStringLiteralLike(arg) && (arg.text === "express" || arg.text === "fastify")) return "app";
  }
  return undefined;
}

function hasDefaultModifier(node: ts.FunctionDeclaration): boolean {
  return ts.getModifiers(node)?.some((m) => m.kind === ts.SyntaxKind.DefaultKeyword) ?? false;
}

function fnKey(rel: string, node: ts.FunctionLikeDeclaration | ts.FunctionDeclaration): string {
  let name: string | undefined;
  if ((ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)) && node.name !== undefined) name = node.name.text;
  else if (ts.isVariableDeclaration(node.parent) && ts.isIdentifier(node.parent.name)) name = node.parent.name.text;
  return `${rel}::fn:${name ?? "@" + node.pos}`;
}

function safeHandler(value: string): string | undefined {
  return /^[\x20-\x7e]{1,512}$/.test(value) ? value : undefined;
}

function handlerName(file: FileInfo, argument: ts.Expression | undefined): string | undefined {
  if (argument === undefined) return undefined;
  const expr = unwrap(argument);
  if (ts.isIdentifier(expr) || ts.isPropertyAccessExpression(expr)) return safeHandler(expr.getText(file.sf));
  return undefined;
}

function diagnostic(code: string, filePath: string): string {
  return JSON.stringify({ type: "diagnostic", code, path: filePath });
}

function claimLine(
  method: string,
  routeParts: string[],
  basis: Basis,
  handler: string | undefined,
  limitations: string[],
  evidence: Evidence,
): string {
  const line: Record<string, unknown> = {
    type: "claim",
    method,
    routeParts,
    routeBasis: basis,
  };
  if (handler !== undefined) line["handler"] = handler;
  line["limitations"] = limitations;
  line["evidence"] = evidence;
  return JSON.stringify(line);
}

/** All lines of the transcript for `options.root`, in order. */
export function analyze(options: AnalyzeOptions): string[] {
  const root = path.resolve(options.root);
  const analysis = new Analysis(root, options.framework);
  analysis.load(options.maxFiles ?? 20000, options.maxFileBytes ?? 1 << 20);

  let claims: string[];
  if (options.framework === "nest") {
    analysis.collectNestPrefixes();
    claims = analysis.nestClaimLines();
  } else {
    analysis.collectRoutes();
    claims = analysis.claimLines();
  }
  claims = [...new Set(claims)];

  const incomplete = [...analysis.incomplete].sort();
  const header = JSON.stringify({
    type: "header",
    contractVersion: 1,
    analyzerName: NAME,
    analyzerVersion: VERSION,
    rulesetId: RULESETS[options.framework],
    framework: options.framework,
  });
  const end = JSON.stringify({
    type: "end",
    claims: claims.length,
    filesScanned: analysis.filesScanned,
    complete: incomplete.length === 0,
    incompleteReasons: incomplete,
  });
  return [header, ...claims, ...analysis.diagnostics, end];
}
