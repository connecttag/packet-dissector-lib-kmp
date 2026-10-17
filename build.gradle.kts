plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kmp.library)
    alias(libs.plugins.kotlin.serialization)
    `maven-publish`
}

group = "org.connecttag.libs.kotlin"
version = "1.0.4"

kotlin {
    jvmToolchain(17)

    android {
        namespace = "org.connecttag.lib.packet.dissector"
        compileSdk = 36
        minSdk = 24
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    jvm {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    sourceSets {
        commonMain.dependencies {
            api(libs.kotlinx.coroutines.core)
            api(libs.kotlinx.serialization.json)
        }
    }
}

publishing {
    publications.withType<MavenPublication> {
        pom {
            name.set("ConnectTag Packet Dissector (KMP)")
            description.set("Cross-platform network packet dissector and payload parsers (DNS Wire, TLS Client/Server Hello, QUIC, HTTP streaming, WebSocket, and HAR exporter) for Kotlin Multiplatform")
            url.set("https://github.com/connecttag/packet-dissector-lib-kmp")
            licenses {
                license {
                    name.set("The Apache License, Version 2.0")
                    url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                }
            }
            developers {
                developer {
                    id.set("connecttagye")
                    name.set("Connect Tag")
                    email.set("connecttagye@gmail.com")
                }
            }
            scm {
                connection.set("scm:git:https://github.com/connecttag/packet-dissector-lib-kmp.git")
                developerConnection.set("scm:git:ssh://git@github.com:connecttag/packet-dissector-lib-kmp.git")
                url.set("https://github.com/connecttag/packet-dissector-lib-kmp/tree/main")
            }
        }
    }
}
