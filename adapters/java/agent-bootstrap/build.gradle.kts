import java.security.MessageDigest
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

plugins {
    java
}

group = "dev.xtrace"
version = "0.1.0"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.14.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.jar {
    archiveFileName.set("xtrace-java-agent.jar")
    manifest {
        attributes(
            "Premain-Class" to "dev.xtrace.agent.bootstrap.XTraceAgent",
            "Can-Redefine-Classes" to "false",
            "Can-Retransform-Classes" to "false",
        )
    }
}

val agentDistCopy = tasks.register<Sync>("agentDistCopy") {
    dependsOn(tasks.jar, project(":agent-runtime").tasks.named("jar"))
    into(layout.buildDirectory.dir("agent-dist"))
    from(tasks.jar)
    into("runtime") {
        from(project(":agent-runtime").configurations.named("runtimeClasspath"))
        from(project(":agent-runtime").tasks.named("jar"))
    }
}

tasks.register("agentDist") {
    group = "distribution"
    description = "Assembles the experimental launch-only Java agent distribution and SHA-256 manifest."
    dependsOn(agentDistCopy)
    doLast {
        val root = layout.buildDirectory.dir("agent-dist").get().asFile
        val jarFiles = root.walkTopDown()
            .filter { it.isFile && it.extension == "jar" }
            .sortedBy { it.relativeTo(root).invariantSeparatorsPath }
        val lines = jarFiles.map { file ->
            val digest = MessageDigest.getInstance("SHA-256")
                .digest(file.readBytes())
                .joinToString("") { byte -> "%02x".format(byte) }
            "$digest  ${file.relativeTo(root).invariantSeparatorsPath}"
        }.toList()
        check(lines.size >= 2) { "agent distribution must contain bootstrap and runtime JARs" }
        root.resolve("manifest.sha256").writeText(lines.joinToString("\n", postfix = "\n"))

        check("posix" in root.toPath().fileSystem.supportedFileAttributeViews()) {
            "agent distribution requires POSIX permissions"
        }
        val directories = PosixFilePermissions.fromString("rwxr-xr-x")
        val files = PosixFilePermissions.fromString("rw-r--r--")
        val entries = root.walkTopDown().toList()
        entries.filter { it.isDirectory }.forEach { entry ->
            Files.setPosixFilePermissions(entry.toPath(), directories)
        }
        entries.filter { it.isFile }.forEach { entry ->
            Files.setPosixFilePermissions(entry.toPath(), files)
        }
        entries.forEach { entry ->
            val expected = if (entry.isDirectory) directories else files
            check(Files.getPosixFilePermissions(entry.toPath()) == expected) {
                "could not normalize agent distribution permissions for ${entry.relativeTo(root)}"
            }
        }
    }
}
