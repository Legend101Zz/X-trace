plugins {
    application
}

group = "dev.xtrace"
version = "0.1.0"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

application {
    applicationName = "xtrace-java-static"
    mainClass.set("dev.xtrace.analyzer.Main")
}

dependencies {
    // Parser only: no symbol solver, no class loading, no execution of analyzed code.
    implementation("com.github.javaparser:javaparser-core:3.28.1")

    testImplementation(platform("org.junit:junit-bom:5.14.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
