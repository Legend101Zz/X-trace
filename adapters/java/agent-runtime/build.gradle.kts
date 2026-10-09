plugins {
    `java-library`
}

group = "dev.xtrace"
version = "0.0.1"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

dependencies {
    implementation(project(":"))
    compileOnly(project(":agent-bootstrap"))
    implementation("net.bytebuddy:byte-buddy:1.18.14")
    implementation("com.google.protobuf:protobuf-java:4.36.2")
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")

    testImplementation(project(":agent-bootstrap"))
    testImplementation(platform("org.junit:junit-bom:5.14.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

tasks.jar {
    archiveFileName.set("xtrace-java-agent-runtime.jar")
}
