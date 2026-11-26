// Official package installation; output files and command diagnostics stay private.
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";

const digest = file => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
function need(ok) { if (!ok) throw new Error("Vendure installed package verification failed"); }
export function installVendurePackage({ repo, archive, directory, sourceCommit }) {
  need(/^[a-f0-9]{40}$/.test(sourceCommit));
  fs.mkdirSync(directory, { mode: 0o700 });
  const prefix = path.join(directory, "prefix"), data = path.join(directory, "data");
  fs.mkdirSync(data, { mode: 0o700 });
  const temporary = path.join(directory, "temporary");
  fs.mkdirSync(temporary, { mode: 0o700 });
  const env = { ...process.env, XTRACE_DATA_HOME: data, TMPDIR: temporary };
  let sequence = 0;
  function command(args) {
    const fd = fs.openSync(path.join(directory, `command-${++sequence}.log`), "wx", 0o600);
    try {
      const result = spawnSync(args[0], args.slice(1), { cwd: repo, env, stdio: ["ignore", fd, fd], timeout: 180000 });
      need(result.status === 0 && !result.error && !result.signal);
    } finally { fs.closeSync(fd); }
  }
  const head = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repo, encoding: "utf8", timeout: 30000 });
  need(head.status === 0 && head.stdout.trim() === sourceCommit);
  const clean = spawnSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: repo, encoding: "utf8", timeout: 30000 });
  need(clean.status === 0 && clean.stdout === "");
  const archiveSha256 = digest(archive);
  command(["sh", "packaging/install.sh", "verify-dist", path.dirname(archive)]);
  command(["python3", "-B", "packaging/verify_package.py", archive, "--repo", repo, "--run-binary"]);
  // Resolve with the package verifier itself, retaining its extraction admission rules.
  const unpacked = path.join(directory, "unpacked"), result = path.join(directory, "resolved.json");
  fs.mkdirSync(unpacked, { mode: 0o700 });
  command(["python3", "-B", "-c", `import importlib.util,json,pathlib,sys,os
spec=importlib.util.spec_from_file_location('vendure_package_verifier',pathlib.Path(sys.argv[1])/'packaging/verify_package.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=m.resolve_root(pathlib.Path(sys.argv[2]),pathlib.Path(sys.argv[3]))
fd=os.open(sys.argv[4],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as f: json.dump(str(p),f)
`, repo, archive, unpacked, result]);
  const packageRoot = JSON.parse(fs.readFileSync(result, "utf8"));
  const relative = "share/xtrace/PACKAGE-MANIFEST.json";
  const manifest = JSON.parse(fs.readFileSync(path.join(packageRoot, relative), "utf8"));
  need(manifest.sourceCommit === sourceCommit && manifest.version === "0.0.1" && manifest.platform === "linux-x86_64");
  need(digest(archive) === archiveSha256);
  command(["sh", path.join(packageRoot, "install.sh"), "--prefix", prefix, "--data-home", data]);
  const installed = path.join(prefix, "current"), cli = path.join(prefix, "bin/xtrace");
  command(["sh", path.join(installed, "install.sh"), "verify", "--prefix", prefix]);
  need(fs.realpathSync(cli) === fs.realpathSync(path.join(installed, "bin/xtrace")));
  for (const file of [relative, "bin/xtrace", "share/xtrace/packs/node/dist/manifest.sha256"]) {
    need(digest(path.join(packageRoot, file)) === digest(path.join(installed, file)));
  }
  need(digest(archive) === archiveSha256);
  return { prefix, cli, data, pack: path.join(installed, "share/xtrace/packs/node/dist"),
    identity: { sourceCommit, archiveSha256, manifestSha256: digest(path.join(installed, relative)),
      cliSha256: digest(cli), nodePackManifestSha256: digest(path.join(installed, "share/xtrace/packs/node/dist/manifest.sha256")) } };
}
