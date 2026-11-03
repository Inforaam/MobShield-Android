# MobShield Android

Open-source mobile app hardening for Android: modular RASP detectors, signal aggregation, and per-build native personalization.

[![Android CI](https://github.com/Inforaam/MobShield-Android/actions/workflows/android-ci.yml/badge.svg)](https://github.com/Inforaam/MobShield-Android/actions/workflows/android-ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![minSdk: 24](https://img.shields.io/badge/minSdk-24-lightgrey.svg)

MobShield runs a set of detection modules, aggregates their weighted signals into `ThreatEvent`s, and reports your app's runtime posture through a listener — so your app can react to root, hooking, debugging, emulator, and integrity-tampering conditions.

## Modules

| Module | Purpose |
|--------|---------|
| `mobshield-core` | Public API facade, aggregator, validation harness, JNI bridge (skeleton) |
| `mobshield-detect-root` | Magisk, Zygisk, Shamiko, KernelSU signals |
| `mobshield-detect-hooks` | Frida, LSPosed, Xposed |
| `mobshield-detect-debugger` | ptrace, TracerPid |
| `mobshield-detect-environment` | Emulator, automation, ADB |
| `mobshield-detect-integrity` | Signature and build anchor |
| `mobshield-gradle-plugin` | Per-build personalization (`io.mobshield.personalize`) |
| `mobshield-sample-app` | Compose integration demo (all detectors) |

## Requirements

- JDK 17+
- Android SDK 34
- Gradle 8.7+ (wrapper included)
- NDK **28.0.13004108** (via SDK Manager; required for **16 KB page size** / Play compliance)

Native modules are built with `ANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON` and 16 KB ELF linker alignment. Rebuild and publish a new tag after upgrading the NDK.

## Install

MobShield is distributed through **JitPack**, built from the tagged releases. Publication to Maven Central (`io.mobshield`) is configured in the build but no release has been published there yet.

### JitPack (single umbrella dependency)

```kotlin
// settings.gradle.kts -> dependencyResolutionManagement.repositories
maven { url = uri("https://jitpack.io") }

// build.gradle.kts
dependencies {
    implementation("com.github.Inforaam:MobShield-Android:1.0.8")
}
```

The umbrella artifact pulls in core and all detect modules transitively.

### Maven Central (not yet available)

These coordinates will resolve once a release is published to Maven Central. They do not resolve today. The `io.mobshield.personalize` Gradle plugin is distributed the same way, so it is not available yet either.

```kotlin
plugins {
    id("io.mobshield.personalize") version "1.0.7"
}

dependencies {
    val mobshield = "1.0.7"
    implementation("io.mobshield:mobshield-core:$mobshield")
    // optional detectors:
    implementation("io.mobshield:mobshield-detect-root:$mobshield")
    implementation("io.mobshield:mobshield-detect-hooks:$mobshield")
    implementation("io.mobshield:mobshield-detect-debugger:$mobshield")
    implementation("io.mobshield:mobshield-detect-environment:$mobshield")
    implementation("io.mobshield:mobshield-detect-integrity:$mobshield")
}
```

## Quick start

Register the detectors, implement a listener, and start MobShield with an application `Context`. It runs in **detect-only** mode by default (it reports; it never terminates your process).

```kotlin
import io.mobshield.core.MobShield
import io.mobshield.core.MobShieldConfig
import io.mobshield.core.MobShieldListener
import io.mobshield.core.ThreatEvent
import io.mobshield.detect.root.RootDetectionRegistrar
import io.mobshield.detect.hooks.HookDetectionRegistrar
import io.mobshield.detect.debugger.DebugDetectionRegistrar
import io.mobshield.detect.environment.EmulatorDetectionRegistrar
import io.mobshield.detect.integrity.IntegrityDetectionRegistrar

val listener = object : MobShieldListener {
    override fun onThreat(event: ThreatEvent) {
        Log.w("MobShield", "threat: ${event.type} ${event.severity} score=${event.score}")
    }

    override fun onAllChecksFinished(events: List<ThreatEvent>) {
        Log.i("MobShield", "scan finished: ${events.size} threat(s)")
    }
}

val config = MobShieldConfig() // detect-only by default
RootDetectionRegistrar.register(context, config)
HookDetectionRegistrar.register(context, config)
DebugDetectionRegistrar.register(context, config)
EmulatorDetectionRegistrar.register(context, config)
IntegrityDetectionRegistrar.register(context, config)
MobShield.start(context, config, listener)
```

Read the current posture at any time, or stop scanning:

```kotlin
val state = MobShield.getState() // riskLevel, activeThreats, running, lastScanMs
MobShield.stop()
```

Common configuration (all optional):

```kotlin
val config = MobShieldConfig.builder()
    .periodicIntervalSec(30)                       // rescan every 30s (default: one scan at start)
    .expectedPackageId("com.example.app")          // anchor package-id integrity
    .expectedSigners(listOf("<sha256-hex>"))       // anchor signing-cert integrity
    .detectOnly(false)                             // opt in to termination
    .terminationPolicy(TerminationPolicy.EXIT_ON_CRITICAL)
    .build()
```

For a signed posture report you can verify on your backend, see `MobShield.currentSignedReport(key)`.

## Build

```bash
./gradlew :mobshield-sample-app:assembleDebug
./gradlew test
```

See [mobshield-sample-app/README.md](mobshield-sample-app/README.md) for a walkthrough.

## Documentation

- [Detection validation matrix](docs/validation.md) — every signal each module emits and the clean vs compromised baselines.
- [Detection notes](docs/detection) — per-detector background.

## Release

Pushing a `v*.*.*` tag makes that release installable through JitPack. The build is also configured to sign and publish to Maven Central through the Sonatype Central Portal, which requires these repository secrets (no release has been published there yet): `SONATYPE_USERNAME`, `SONATYPE_PASSWORD`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`.

Local verification:

```bash
./gradlew :mobshield-core:publishToMavenLocal -PVERSION_NAME=1.0.7-SNAPSHOT
```

## License

- Kotlin and Gradle sources: [Apache-2.0](LICENSE)
- Native core (when implemented): [LICENSE-BSL](LICENSE-BSL), Change Date 2028-05-25
