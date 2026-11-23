plugins {
    id("com.android.application")
    id("io.mobshield.personalize")
}

mobshield {
    expectedSigningCertSha256 =
        "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
    expectedPackageName = "com.mobshield.stub"
    expectedInstallers = listOf("com.android.vending")
    aggressive = false
}

android {
    namespace = "com.mobshield.stub"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.mobshield.stub"
        minSdk = 24
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"
    }
}
