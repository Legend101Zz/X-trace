plugins {
    application
    id("com.google.protobuf") version "0.10.0"
}

group = "dev.xtrace"
version = "0.1.0"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

application {
    applicationName = "xtrace-java-synthetic"
    mainClass.set("dev.xtrace.adapter.SyntheticClientMain")
}

dependencies {
    implementation("com.google.protobuf:protobuf-java:4.36.2")
    implementation("org.conscrypt:conscrypt-openjdk-uber:2.7.0")
    implementation("com.fasterxml.jackson.core:jackson-core:2.22.3")
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")

    testImplementation(platform("org.junit:junit-bom:5.14.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

sourceSets {
    main {
        proto {
            // Resolve from adapters/java to the workspace's canonical schemas.
            srcDir("../../schema/proto")
        }
        resources {
            srcDir("fixtures")
        }
    }
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:4.36.2"
    }
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

allprojects {
    dependencyLocking {
        lockAllConfigurations()
    }
}

tasks.register("agentDist") {
    group = "distribution"
    description = "Assembles the experimental launch-only Java agent distribution."
    dependsOn(":agent-bootstrap:agentDist")
}

tasks.register("fixtureBootJar") {
    group = "distribution"
    description = "Builds the independent Spring MVC fixture executable."
    dependsOn(":spring-fixture:bootJar")
}

tasks.register<Sync>("attachHelperDist") {
    group = "distribution"
    description = "Assembles the standalone JVM attach helper executable JAR."
    dependsOn(":attach-helper:jar")
    into(layout.buildDirectory.dir("attach-helper-dist"))
    from(project(":attach-helper").tasks.named("jar")) {
        rename { "xtrace-attach.jar" }
    }
}

tasks.register<Sync>("javaPackDist") {
    group = "distribution"
    description = "Assembles the unsigned fixture-only Java development attach pack."
    dependsOn("attachHelperDist", "agentDist")
    into(layout.buildDirectory.dir("java-pack-dist"))
    outputs.file(layout.buildDirectory.file("java-pack-dist/pack.manifest"))
    from(layout.buildDirectory.dir("attach-helper-dist")) {
        into("attach")
    }
    from(project(":agent-bootstrap").layout.buildDirectory.dir("agent-dist")) {
        into("agent")
    }
    doLast {
        val root = layout.buildDirectory.dir("java-pack-dist").get().asFile
        val paths = java.nio.file.Files.walk(root.toPath()).use { stream ->
            val iterator = stream.iterator()
            val bounded = mutableListOf<java.nio.file.Path>()
            while (iterator.hasNext()) {
                check(bounded.size < 96) { "Java pack exceeds the 96-entry tree limit" }
                bounded.add(iterator.next())
            }
            bounded
        }
        check(paths.drop(1).none(java.nio.file.Files::isSymbolicLink)) {
            "Java pack cannot contain symbolic links"
        }
        check(paths.drop(1).all {
            java.nio.file.Files.isDirectory(it, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                || java.nio.file.Files.isRegularFile(it, java.nio.file.LinkOption.NOFOLLOW_LINKS)
        }) { "Java pack cannot contain special files" }
        val actualDirectories = paths.drop(1)
            .filter { java.nio.file.Files.isDirectory(it, java.nio.file.LinkOption.NOFOLLOW_LINKS) }
            .map { root.toPath().relativize(it).toString().replace(java.io.File.separatorChar, '/') }
            .toSet()
        check(actualDirectories == setOf("attach", "agent", "agent/runtime")) {
            "Java pack directory membership does not match"
        }
        val files = paths.drop(1)
            .filter { java.nio.file.Files.isRegularFile(it, java.nio.file.LinkOption.NOFOLLOW_LINKS) }
            .map { it.toFile() }
            .onEach { file ->
                check(file.length() <= 256L * 1024 * 1024) {
                    "Java pack file exceeds the bounded distribution size"
                }
            }
            .sortedBy { it.relativeTo(root).invariantSeparatorsPath }
        val totalBytes = files.sumOf { it.length() }
        check(totalBytes <= 512L * 1024 * 1024) {
            "Java pack exceeds the bounded distribution size"
        }
        check(files.any { it.relativeTo(root).invariantSeparatorsPath == "attach/xtrace-attach.jar" }) {
            "Java pack is missing the standalone attach helper"
        }
        check(files.any { it.relativeTo(root).invariantSeparatorsPath == "agent/manifest.sha256" }) {
            "Java pack is missing the agent manifest"
        }
        check(files.any { it.relativeTo(root).invariantSeparatorsPath == "agent/xtrace-java-agent.jar" }) {
            "Java pack is missing the bootstrap agent"
        }
        check(files.any {
            val path = it.relativeTo(root).invariantSeparatorsPath
            path.startsWith("agent/runtime/") && path.endsWith(".jar")
        }) { "Java pack is missing agent runtime JARs" }

        val lines = files.map { file ->
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            val hash = file.inputStream().use { input ->
                val buffer = ByteArray(32 * 1024)
                var count: Int
                while (input.read(buffer).also { count = it } != -1) {
                    digest.update(buffer, 0, count)
                }
                digest.digest()
            }.joinToString("") { byte -> "%02x".format(byte) }
            "$hash  ${file.relativeTo(root).invariantSeparatorsPath}"
        }
        root.resolve("pack.manifest").writeText(lines.joinToString("\n", postfix = "\n"))

        check("posix" in root.toPath().fileSystem.supportedFileAttributeViews()) {
            "Java pack requires POSIX permissions"
        }
        val directoryPermissions = java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x")
        val filesMode = java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--")
        java.nio.file.Files.setPosixFilePermissions(root.resolve("pack.manifest").toPath(), filesMode)
        paths.asReversed().forEach { entry ->
            val permissions = if (java.nio.file.Files.isDirectory(entry, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                directoryPermissions
            } else {
                filesMode
            }
            java.nio.file.Files.setPosixFilePermissions(entry, permissions)
        }
    }
}

// The strict CLI integration target consumes the generated pack. Make the
// canonical Gradle installation gate produce it deterministically first.
tasks.named<Sync>("installDist") {
    dependsOn("javaPackDist")
}
