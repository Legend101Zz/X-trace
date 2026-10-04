"""Lockfile readers shared by sbom.py and licenses.py (python3 stdlib only, >=3.11)."""
from __future__ import annotations

import json
import subprocess
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote

JAVA_SHIPPED_CONFIG = "runtimeClasspath"
# Gradle projects whose runtimeClasspath lands in the release payload (javaPackDist). The root
# synthetic client and the spring fixture are test/dev only.
JAVA_SHIPPED_PROJECTS = {"agent-bootstrap", "agent-runtime", "attach-helper"}


def purl_cargo(name, version):
    return f"pkg:cargo/{quote(name)}@{quote(version)}"


def purl_maven(group, name, version):
    return f"pkg:maven/{quote(group)}/{quote(name)}@{quote(version)}"


def purl_npm(name, version):
    if name.startswith("@"):
        scope, rest = name.split("/", 1)
        return f"pkg:npm/{quote(scope)}/{quote(rest)}@{quote(version)}"
    return f"pkg:npm/{quote(name)}@{quote(version)}"


def read_cargo(root: Path, metadata_file: Path | None = None, run_metadata: bool = True):
    """Components from Cargo.lock; licenses/scope enriched from `cargo metadata` when available.

    Returns (components, info). component keys: ecosystem,name,version,purl,scope,hashes,license,
    license_file_dir,repository,source,workspace.
    """
    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    meta = None
    if metadata_file:
        meta = json.loads(Path(metadata_file).read_text(encoding="utf-8"))
    elif run_metadata:
        try:
            out = subprocess.run(
                ["cargo", "metadata", "--format-version", "1", "--locked"],
                cwd=root, check=True, capture_output=True, text=True,
            ).stdout
            meta = json.loads(out)
        except (OSError, subprocess.CalledProcessError):
            meta = None
    by_key = {}
    if meta:
        for p in meta["packages"]:
            by_key[(p["name"], p["version"])] = p
    scope = {}
    if meta and meta.get("resolve"):
        nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
        ids = {p["id"]: (p["name"], p["version"]) for p in meta["packages"]}
        roots = [i for i, (n, _) in ids.items() if n == "xtrace-cli"]
        seen_normal, seen_build = set(), set()
        stack = [(r, "normal") for r in roots]
        while stack:
            nid, mode = stack.pop()
            target = seen_normal if mode == "normal" else seen_build
            if nid in target:
                continue
            target.add(nid)
            for dep in nodes[nid]["deps"]:
                for dk in dep["dep_kinds"]:
                    kind = dk["kind"]
                    if kind == "dev":
                        continue
                    stack.append((dep["pkg"], "normal" if (kind is None and mode == "normal") else "build"))
        for i, key in ids.items():
            scope[key] = "required" if i in seen_normal else ("optional" if i in seen_build else "excluded")
    comps = []
    for p in lock["package"]:
        key = (p["name"], p["version"])
        m = by_key.get(key, {})
        if meta and key not in by_key:
            continue  # not part of this platform's resolved build graph (e.g. windows/wasm-only crates)
        workspace = "source" not in p
        s = scope.get(key, "required") if meta else "required"
        if s == "excluded":
            continue
        hashes = {}
        if "checksum" in p:
            hashes["SHA-256"] = p["checksum"]
        comps.append({
            "ecosystem": "cargo", "name": p["name"], "version": p["version"],
            "purl": purl_cargo(*key), "scope": s, "hashes": hashes,
            "license": m.get("license"), "license_file": m.get("license_file"),
            "manifest_dir": str(Path(m["manifest_path"]).parent) if m.get("manifest_path") else None,
            "repository": m.get("repository"), "source": p.get("source"), "workspace": workspace,
        })
    comps.sort(key=lambda c: (c["name"], c["version"]))
    return comps, {"cargoMetadata": bool(meta), "lockPackages": len(lock["package"])}


def read_gradle(java_dir: Path):
    """Components from every gradle.lockfile, hashes from dependency-verification metadata."""
    ns = {"v": "https://schema.gradle.org/dependency-verification"}
    vm = ET.parse(java_dir / "gradle" / "verification-metadata.xml").getroot()
    sha = {}
    for c in vm.findall("v:components/v:component", ns):
        g, n, v = c.get("group"), c.get("name"), c.get("version")
        for a in c.findall("v:artifact", ns):
            s = a.find("v:sha256", ns)
            if s is not None:
                sha.setdefault((g, n, v), {})[a.get("name")] = s.get("value")
    found = {}
    for lf in sorted(java_dir.rglob("gradle.lockfile")):
        if "build" in lf.relative_to(java_dir).parts:
            continue
        project = lf.parent.name if lf.parent != java_dir else "(root)"
        for line in lf.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            coord, _, configs = line.partition("=")
            parts = coord.split(":")
            if len(parts) != 3:
                continue
            g, n, v = parts
            entry = found.setdefault((g, n, v), set())
            for c in configs.split(","):
                if c:
                    entry.add(f"{project}:{c}")
    comps = []
    for (g, n, v), configs in sorted(found.items()):
        arts = sha.get((g, n, v), {})
        jar = arts.get(f"{n}-{v}.jar")
        shipped = any(
            cfg.split(":", 1)[0] in JAVA_SHIPPED_PROJECTS and cfg.endswith(":" + JAVA_SHIPPED_CONFIG)
            for cfg in configs
        )
        comps.append({
            "ecosystem": "maven", "group": g, "name": n, "version": v,
            "purl": purl_maven(g, n, v),
            "scope": "required" if shipped else "excluded",
            "hashes": {"SHA-256": jar} if jar else {},
            "license": None, "license_file": None, "manifest_dir": None, "repository": None,
            "source": "https://repo.maven.apache.org/maven2", "workspace": False,
            "configs": sorted(configs), "verified_artifacts": sorted(arts),
        })
    return comps, {"verificationComponents": len(sha), "lockedComponents": len(comps)}


def read_npm(lock_path: Path, label: str):
    d = json.loads(lock_path.read_text(encoding="utf-8"))
    comps = []
    for path, p in sorted(d.get("packages", {}).items()):
        if not path.startswith("node_modules/") or p.get("link"):
            continue
        name = p.get("name") or path.split("node_modules/")[-1]
        version = p.get("version")
        if not version:
            continue
        hashes = {}
        integ = p.get("integrity", "")
        if integ.startswith("sha512-"):
            import base64
            hashes["SHA-512"] = base64.b64decode(integ[7:]).hex()
        elif integ.startswith("sha1-"):
            import base64
            hashes["SHA-1"] = base64.b64decode(integ[5:]).hex()
        comps.append({
            "ecosystem": "npm", "name": name, "version": version, "purl": purl_npm(name, version),
            "scope": "excluded" if p.get("dev") else ("optional" if p.get("optional") else "required"),
            "hashes": hashes, "license": p.get("license"), "license_file": None,
            "manifest_dir": None, "repository": None, "source": p.get("resolved"),
            "workspace": False, "lockfile": label,
        })
    return comps, {"lockfile": label, "packages": len(comps)}


NPM_LOCKS = {"adapters/node": "node-adapter", "web/app": "web-viewer"}


def read_all(root: Path, cargo_metadata: Path | None = None, run_cargo_metadata: bool = True):
    info = {}
    comps = []
    c, info["cargo"] = read_cargo(root, cargo_metadata, run_cargo_metadata)
    comps += c
    c, info["gradle"] = read_gradle(root / "adapters" / "java")
    comps += c
    for rel, label in NPM_LOCKS.items():
        c, info[label] = read_npm(root / rel / "package-lock.json", label)
        comps += c
    return comps, info
