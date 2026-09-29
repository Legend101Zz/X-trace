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

dependencyLocking {
    lockAllConfigurations()
}
