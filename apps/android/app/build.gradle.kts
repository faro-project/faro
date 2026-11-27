import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

// The Rust core (crates/faro-android) is built into native libraries and
// Kotlin bindings (package org.faro.core) by build-android.sh. It needs the
// Android NDK, cargo-ndk and the Rust Android targets (see ../README.md).
val repoRoot = rootProject.projectDir.resolve("../..").canonicalFile
val generatedDir = layout.buildDirectory.dir("generated/faro")

// -Pfaro.generatedDir=<dir> uses bindings and libraries somebody already
// built (a directory with jniLibs/<abi>/libfaro_android.so and kotlin/).
val prebuilt = providers.gradleProperty("faro.generatedDir")
val faroGenerated: Provider<Directory> = prebuilt
    .map { rootProject.layout.projectDirectory.dir(it) }
    .orElse(generatedDir)

val buildFaroCore = tasks.register<Exec>("buildFaroCore") {
    group = "build"
    description = "Builds the Rust core (libfaro_android.so) and its UniFFI Kotlin bindings."
    val script = repoRoot.resolve("crates/faro-android/build-android.sh")
    val out = generatedDir
    workingDir = repoRoot
    // Git Bash on Windows, /bin/bash elsewhere: `bash` is on PATH in both.
    commandLine("bash", script.absolutePath, out.get().asFile.absolutePath)
    inputs.dir(repoRoot.resolve("crates/faro-android")).withPropertyName("faroAndroidCrate")
    inputs.file(repoRoot.resolve("Cargo.lock")).withPropertyName("cargoLock")
    outputs.dir(out)
    onlyIf { !prebuilt.isPresent }
}

android {
    namespace = "org.faro.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.faro.android"
        minSdk = 30
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-beta.1"
        // The Rust core is built for these.
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets.getByName("main") {
        jniLibs.srcDir(faroGenerated.map { it.dir("jniLibs") })
        java.srcDir(faroGenerated.map { it.dir("kotlin") })
    }

    packaging {
        // The Rust library carries no debug symbols we ship; keep it as built.
        jniLibs.keepDebugSymbols += "**/libfaro_android.so"
        // JNA loads libfaro_android.so by name; have the installer unpack the libraries.
        jniLibs.useLegacyPackaging = true
    }

    lint {
        // Lint needs the generated sources; the unit tests and the build are the CI gate.
        abortOnError = false
    }
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

// The generated Kotlin and the .so must exist before anything compiles or packages.
tasks.named("preBuild") { dependsOn(buildFaroCore) }
tasks.withType<KotlinCompile>().configureEach { dependsOn(buildFaroCore) }

dependencies {
    implementation(libs.androidx.core.ktx)
    // UniFFI's Kotlin bindings use JNA; on Android it is the AAR (it carries libjnidispatch.so).
    implementation(libs.jna.get().let { "${it.module}:${it.versionConstraint.requiredVersion}@aar" })
    testImplementation(libs.junit)
}
