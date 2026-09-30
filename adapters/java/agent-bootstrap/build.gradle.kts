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

tasks.register<Sync>("agentDist") {
    dependsOn(tasks.jar, project(":agent-runtime").tasks.named("jar"))
    into(layout.buildDirectory.dir("agent-dist"))
    from(tasks.jar)
    into("runtime") {
        from(project(":agent-runtime").configurations.named("runtimeClasspath"))
        from(project(":agent-runtime").tasks.named("jar"))
    }
}
