plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.detekt)
    alias(libs.plugins.ktlint)
    id("io.mobshield.personalize")
}

// ---------------------------------------------------------------------------
// MobShield personalization (per-build native anchors)
// Replace expectedSigningCertSha256 with your release/debug cert for mobshieldVerify.
// ---------------------------------------------------------------------------
mobshield {
    expectedSigningCertSha256 =
        "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    expectedPackageName = "io.mobshield.sampleapp"
    expectedInstallers = listOf("com.android.vending")
    aggressive = false
}

android {
    namespace = "io.mobshield.sampleapp"
    compileSdk {
        version =
            release(libs.versions.compileSdk.get().toInt()) {
                minorApiLevel = libs.versions.compileSdkMinor.get().toInt()
            }
    }

    defaultConfig {
        applicationId = "io.mobshield.sampleapp"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.compileSdk.get().toInt()
        versionCode = 1
        versionName = "0.1.0"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    // Same modules as a Maven Central install. The :mobshield umbrella is not used here: it takes
    // the modules as compileOnly and only bundles them into its JitPack AAR, so a project
    // dependency on it would leave the detectors out of this APK.
    implementation(project(":mobshield-core"))
    implementation(project(":mobshield-detect-root"))
    implementation(project(":mobshield-detect-hooks"))
    implementation(project(":mobshield-detect-debugger"))
    implementation(project(":mobshield-detect-environment"))
    implementation(project(":mobshield-detect-integrity"))

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)
    implementation(libs.activity.compose)
    implementation(libs.navigation.compose)
    implementation(libs.lifecycle.runtime.compose)
    implementation(libs.lifecycle.viewmodel.compose)
    implementation(libs.timber)
    implementation(libs.coroutines.android)

    debugImplementation(libs.compose.ui.tooling.preview)
}

detekt {
    config.setFrom(files("${rootProject.projectDir}/detekt.yml"))
}
