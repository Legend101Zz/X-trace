"""Qualify the two real nested Jersey artifacts independently of product probe installation."""
import hashlib
import io
import re
import zipfile

# Published Maven Central artifacts. The service and invoker class files match across both releases.
PINNED = {
    "jersey-container-servlet-core": (
        "org/glassfish/jersey/servlet/ServletContainer.class",
        "933e70fb8cf969087bd8b862bbce67a54cd39e9533e91e095f8682d0fb43bada",
        "org.glassfish.jersey.containers.jersey-container-servlet-core",
        {"3.1.10": "fd15e7e37215d772ccdae8d4076c41a11ad3fec9ca88a1f8a8f6dacf4663bb69",
         "3.1.11": "4c93b928d93037d7250ab1db9b9eb5e2bd12cf9e67cd48d25dcc835249d47e40"},
    ),
    "jersey-server": (
        "org/glassfish/jersey/server/model/ResourceMethodInvoker.class",
        "b5ec8f9270cfefa2f634d7c40547a4c8f1c4ff3575db9f4cbc63563692f7d63e",
        "org.glassfish.jersey.core.jersey-server",
        {"3.1.10": "1b33a9be417b72f7ceef3afe9780781b66122b0f1db78f2f82502988072cfab0",
         "3.1.11": "7dde2adf6600f3e8f723e37a8c96c31838a682f8db854fdcfcf4f00695d6f903"},
    ),
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def verify_fixture(path, version):
    with zipfile.ZipFile(path) as app:
        names = app.namelist()
        require(len(names) == len(set(names)), "duplicate fixture jar member")
        common_digest = {"3.1.10": "b8df5de87d48d6abf555f340755a056c8cb29a660af958e959db8a4cb3552b54",
                         "3.1.11": "ec516d7c2fdcfcd7eb7739eacf3cd6914e17a1595fd45826b33c8765965981b2"}
        for artifact, expected, digest in (
            ("spring-boot", "3.5.15", "1d3ea175f61f492d95cbca457d6cc9cf1b696b550422c1b424d50dfa58f7da15"),
            ("tomcat-embed-core", "10.1.55", "82473f841824095e03f2c938c18707e44e388e34fb1735b2b338bb4f22fd54f0"),
            ("jersey-common", version, common_digest[version]),
        ):
            candidates = [n for n in names if re.fullmatch(rf"BOOT-INF/lib/{artifact}-[0-9][^/]*\.jar", n)]
            require(candidates == [f"BOOT-INF/lib/{artifact}-{expected}.jar"], "fixture runtime version")
            require(hashlib.sha256(app.read(candidates[0])).hexdigest() == digest, "fixture runtime digest")
        probe_inputs = {}
        for artifact, (target, class_digest, bundle, hashes) in PINNED.items():
            jar = f"BOOT-INF/lib/{artifact}-{version}.jar"
            require([n for n in names if re.fullmatch(rf"BOOT-INF/lib/{artifact}-[0-9][^/]*\.jar", n)] == [jar],
                    "ambiguous Jersey bundle")
            data = app.read(jar)
            require(hashlib.sha256(data).hexdigest() == hashes[version], "Jersey artifact digest")
            with zipfile.ZipFile(io.BytesIO(data)) as lib:
                require(hashlib.sha256(lib.read(target)).hexdigest() == class_digest, "Jersey class digest")
                manifest_bytes = lib.read("META-INF/MANIFEST.MF")
                manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
                name = "service" if artifact == "jersey-container-servlet-core" else "invoker"
                probe_inputs[name] = (class_digest, manifest_digest)
                if artifact == "jersey-container-servlet-core":
                    component = lib.read("org/glassfish/jersey/servlet/WebComponent.class")
                    expected = {"3.1.10": "334d3a5218419342fe56a870a4dd63a44e3942cbbf7298f8a8aef789c180d585",
                                "3.1.11": "d437beb05b3ccaf0dcace45d11d25559dbcec5b3224aee601338abdd60d6ca11"}
                    require(hashlib.sha256(component).hexdigest() == expected[version], "Jersey binding image")
                    probe_inputs["component"] = (expected[version], manifest_digest)
                manifest = manifest_bytes.decode().replace("\r\n", "\n").replace("\n ", "")
                attrs = dict(line.split(": ", 1) for line in manifest.split("\n\n", 1)[0].splitlines())
                require((attrs.get("Bundle-Version"), attrs.get("Bundle-SymbolicName")) == (version, bundle),
                        "Jersey archive manifest")
        prefix = "BOOT-INF/classes/fixture/jersey/"
        classes = {n[len(prefix):]: hashlib.sha256(app.read(n)).hexdigest() for n in names
                   if n.startswith(prefix) and n.endswith(".class")}
        require(set(classes) == {"Fixture.class", "Fixture$Refusal.class", "Fixture$Resources.class",
                                 "Groups.class", "Items.class"}, "fixture class inventory")
        return classes, probe_inputs
