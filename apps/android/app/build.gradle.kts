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

// -Pfaro.onnx=false builds the core without ONNX Runtime, and so without the model.
val withOnnx = providers.gradleProperty("faro.onnx").orNull != "false"

// -Pfaro.modelDir=<dir> (or FARO_MODEL_DIR) packages the image model: the directory that
// crates/faro-detect/models/opennsfw/build.sh writes (manifest.json, opennsfw-int8.onnx and
// NOTICE.txt). Without it the app has no model and rates from context signals only.
val modelDir: File? = (providers.gradleProperty("faro.modelDir").orNull ?: System.getenv("FARO_MODEL_DIR"))
    ?.takeIf { it.isNotBlank() && withOnnx }
    ?.let { rootProject.layout.projectDirectory.asFile.resolve(it).canonicalFile }

// The shell that runs build-android.sh. On Windows `bash` on PATH is often
// WSL's (System32\bash.exe), which can't see this toolchain, so prefer Git
// Bash; -Pfaro.bash=<path> overrides it.
val bash: String = providers.gradleProperty("faro.bash").orNull
    ?: if (System.getProperty("os.name").startsWith("Windows")) {
        listOfNotNull(System.getenv("ProgramFiles"), System.getenv("ProgramW6432"))
            .map { File(it, "Git/bin/bash.exe") }
            .firstOrNull { it.isFile }?.path ?: "bash"
    } else {
        "bash"
    }

val buildFaroCore = tasks.register<Exec>("buildFaroCore") {
    group = "build"
    description = "Builds the Rust core (libfaro_android.so) and its UniFFI Kotlin bindings."
    val out = generatedDir
    workingDir = repoRoot
    // Forward slashes: bash reads backslashes in Windows paths as escapes.
    commandLine(
        bash,
        "crates/faro-android/build-android.sh",
        out.get().asFile.absolutePath.replace('\\', '/'),
        *(if (withOnnx) emptyArray() else arrayOf("--no-onnx")),
    )
    inputs.property("withOnnx", withOnnx)
    inputs.dir(repoRoot.resolve("crates/faro-android")).withPropertyName("faroAndroidCrate")
    inputs.file(repoRoot.resolve("Cargo.lock")).withPropertyName("cargoLock")
    outputs.dir(out)
    onlyIf { !prebuilt.isPresent }
}

// The assets: ONNX Runtime's notices (from the core build) and, with -Pfaro.modelDir, the image
// model (assets/model/opennsfw/) and its notice. ModelAssets copies the model to app-private
// storage at startup.
val faroAssets = layout.buildDirectory.dir("generated/faro-assets")
val prepareFaroAssets = tasks.register<Sync>("prepareFaroAssets") {
    val dir = modelDir
    into(faroAssets)
    from(faroGenerated.map { it.dir("notices") }) { into("notices") }
    if (dir != null) {
        for (f in listOf("manifest.json", "opennsfw-int8.onnx")) {
            if (!dir.resolve(f).isFile) {
                throw GradleException("faro.modelDir $dir has no $f (crates/faro-detect/models/opennsfw/build.sh writes it)")
            }
        }
        from(dir) {
            include("manifest.json", "opennsfw-int8.onnx")
            into("model/opennsfw")
        }
        val notice = dir.resolve("NOTICE.txt")
        if (notice.isFile) {
            from(notice) {
                into("notices")
                rename { "opennsfw.txt" }
            }
        } else {
            // A model directory without the NOTICE.txt that build.sh writes: make it from the manifest.
            @Suppress("UNCHECKED_CAST")
            val manifest = groovy.json.JsonSlurper().parse(dir.resolve("manifest.json")) as Map<String, Any?>
            @Suppress("UNCHECKED_CAST")
            val attribution = manifest["attribution"] as Map<String, Any?>
            doLast {
                val text = "OpenNSFW image classifier (${manifest["name"]} ${manifest["version"]})\n\n" +
                    "Faro's on-device image classifier is OpenNSFW by ${attribution["author"]}, used\n" +
                    "under the ${manifest["license"]} licence below.\n\n" +
                    "Source:  ${attribution["source_url"]}\n" +
                    "Licence: ${attribution["license_url"]}\n" +
                    "Changes: ${attribution["changes"]}\n\n${manifest["license_text"]}\n"
                faroAssets.get().asFile.resolve("notices/opennsfw.txt").apply { parentFile.mkdirs() }.writeText(text)
            }
        }
    }
    inputs.property("modelDir", dir?.path ?: "")
    dependsOn(buildFaroCore)
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
        assets.srcDir(faroAssets)
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
tasks.matching { it.name.startsWith("merge") && it.name.endsWith("Assets") }.configureEach { dependsOn(prepareFaroAssets) }

dependencies {
    implementation(libs.androidx.core.ktx)
    // UniFFI's Kotlin bindings use JNA; on Android it is the AAR (it carries libjnidispatch.so).
    implementation(libs.jna.get().let { "${it.module}:${it.versionConstraint.requiredVersion}@aar" })
    testImplementation(libs.junit)
}
