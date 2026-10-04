plugins {
    application
    java
}

group = "dev.xtrace"
version = "0.1.0"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

application {
    applicationName = "xtrace-attach"
    mainClass.set("io.xtrace.attach.Main")
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.14.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.test {
    useJUnitPlatform {
        excludeTags("acceptance")
    }
}

tasks.register<Test>("acceptanceTest") {
    group = "verification"
    description = "Runs the disposable already-running Spring fixture attach journey."
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    useJUnitPlatform {
        includeTags("acceptance")
    }
    listOf(
        "xtrace.cli",
        "xtrace.target.java",
        "xtrace.helper.java",
        "xtrace.agent",
        "xtrace.fixture",
        "xtrace.helper",
        "xtrace.workspace",
        "xtrace.attach.evidence.dir",
    ).forEach { property ->
        System.getProperty(property)?.let { systemProperty(property, it) }
    }
    shouldRunAfter(tasks.test)
}

tasks.jar {
    archiveFileName.set("xtrace-attach.jar")
    manifest {
        attributes(
            "Main-Class" to "io.xtrace.attach.Main",
            "Add-Modules" to "jdk.attach,jdk.security.auth",
        )
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.addAll(listOf("--add-modules", "jdk.attach"))
}

tasks.withType<JavaExec>().configureEach {
    jvmArgs("--add-modules=jdk.attach")
}

tasks.withType<Test>().configureEach {
    jvmArgs("--add-modules=jdk.attach")
}

application {
    applicationDefaultJvmArgs = listOf("--add-modules=jdk.attach")
}
