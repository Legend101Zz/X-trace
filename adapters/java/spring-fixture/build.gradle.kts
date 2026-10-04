plugins {
    java
    id("org.springframework.boot") version "4.1.1"
}

group = "dev.xtrace.fixture"
version = "0.1.0"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

val sourceAttestation = configurations.create("sourceAttestation")

dependencies {
    implementation(platform("org.springframework.boot:spring-boot-dependencies:4.1.1"))
    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    runtimeOnly("com.h2database:h2")

    testImplementation(platform("org.junit:junit-bom:5.14.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    add(sourceAttestation.name, project(":agent-runtime"))
}

val generatedAttestationResources = layout.buildDirectory.dir("generated/source-attestation-resources")
val fixtureSourceSnapshot = layout.buildDirectory.dir("generated/source-attestation-inputs")
sourceSets.main { resources.srcDir(generatedAttestationResources) }

val fixtureSourceNames = listOf("OrderController.java", "OrderService.java", "OrderRepository.java")
val snapshotFixtureSources = tasks.register("snapshotFixtureSources") {
    val sourceDirectory = layout.projectDirectory.dir("src/main/java/dev/xtrace/fixture")
    inputs.files(fixtureSourceNames.map { sourceDirectory.file(it) })
    outputs.dir(fixtureSourceSnapshot)
    doLast {
        val destination = fixtureSourceSnapshot.get().asFile.resolve("dev/xtrace/fixture")
        destination.mkdirs()
        fixtureSourceNames.forEach { name ->
            sourceDirectory.file(name).asFile.copyTo(destination.resolve(name), overwrite = true)
        }
    }
}

tasks.named("compileJava") { dependsOn(snapshotFixtureSources) }

val generateSourceAttestation = tasks.register<JavaExec>("generateSourceAttestation") {
    dependsOn(":agent-runtime:jar", tasks.named("compileJava"))
    classpath = sourceAttestation
    mainClass.set("dev.xtrace.agent.runtime.SourceAttestationGenerator")
    inputs.dir(fixtureSourceSnapshot)
    inputs.dir(sourceSets.main.get().output.classesDirs.singleFile)
    val attestation = generatedAttestationResources.map { it.file("META-INF/xtrace/source-attestation.tsv") }
    outputs.file(attestation)
    doFirst {
        val classes = sourceSets.main.get().output.classesDirs.singleFile
        args(
            rootProject.projectDir.resolve("../..").canonicalPath,
            classes.absolutePath,
            attestation.get().asFile.absolutePath,
            fixtureSourceSnapshot.get().asFile.absolutePath
        )
    }
}

tasks.named("processResources") { dependsOn(generateSourceAttestation) }

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.bootJar {
    archiveFileName.set("xtrace-spring-fixture.jar")
}
