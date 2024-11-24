plugins {
    kotlin("jvm") version "2.0.20"
    id("maven-publish")
}

group = "io.github.ktosint"
version = "0.5.0"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")

    // ADD THESE TO YOUR PROJECT
    implementation("com.beust:klaxon:5.5")
    implementation("io.ktor:ktor-client-core:2.3.12")
    implementation("io.ktor:ktor-client-cio:2.3.12")
}

kotlin {
    jvmToolchain(19)
}

publishing {
    repositories {
        maven {
            name = "Sonatype"
            url = uri("https://oss.sonatype.org/service/local/staging/deploy/maven2/")
            credentials {
                username = project.findProperty("username").toString()
                password = project.findProperty("password").toString()
            }
        }
    }
}