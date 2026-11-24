plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.chaquo.python")
}

android {
    namespace = "com.kavach.edge"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.kavach.edge"
        minSdk = 24          // Chaquopy minimum; NumPy cp312 wheel is android_21, so 24 is fine
        targetSdk = 35
        versionCode = 1
        versionName = "0.1"
        ndk {
            abiFilters += listOf("arm64-v8a")   // Vivo V40e (Dimensity 7300) is arm64; no other ABIs
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    // ExecuTorch runtime with the LLM runner (XNNPACK CPU backend). 1.1.0 is the version
    // LlamaDemo pins, confirmed on the V40e with our SpinQuant INT4 .pte (24 Nov).
    implementation("org.pytorch:executorch-android:1.1.0")
}

// ---------------------------------------------------------------------------------------------
// Stage the ONE copy of the detector into the build folder.
// kavach-edge/kavach is copied (never edited) to build/kavach-staging/kavach, and its model
// files to build/kavach-staging/models. The detector finds its models at
// dirname(dirname(kavach/__file__))/models, so keeping them as siblings means no code change.
// Only these two folders are packaged: no data/, results/, report/, study/ ...
// ---------------------------------------------------------------------------------------------
val kavachEdge = rootProject.projectDir.resolve("../kavach-edge")
val stagingDir = layout.buildDirectory.dir("kavach-staging")

val stageDetector by tasks.registering(Sync::class) {
    into(stagingDir)
    from(kavachEdge.resolve("kavach")) {
        into("kavach")
        exclude("**/__pycache__/**", "**/*.pyc")
    }
    from(kavachEdge.resolve("models")) {
        into("models")
        exclude("**/__pycache__/**")
    }
}
tasks.named("preBuild") { dependsOn(stageDetector) }
// Chaquopy's merge<Variant>PythonSources task reads the staging folder, so tell Gradle the order.
tasks.matching { it.name.matches(Regex("merge\\w*PythonSources")) }.configureEach { dependsOn(stageDetector) }

chaquopy {
    defaultConfig {
        version = "3.12"                 // matches the laptop's Python 3.12 (also used as buildPython)
        pip {
            install("numpy==1.26.2")     // only prebuilt arm64 NumPy for cp312 in Chaquopy's repo
        }
    }
    sourceSets {
        getByName("main") {
            srcDir("src/main/python")                       // our thin bridge
            srcDir(stagingDir.get().asFile.path)            // staged kavach + models
        }
    }
}
