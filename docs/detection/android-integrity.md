# Android Integrity Detection (mobshield-detect-integrity)

Kotlin-only module for package signature, package name, install source, APK checksum, and native library checksum verification. Signals map to `APP_INTEGRITY` and `UNOFFICIAL_STORE` (MASVS-RES-2).

## Signal catalog

| Signal | Technique | Default weight | Default confidence |
|--------|-----------|----------------|------------------|
| `android.integrity.signature` | Signing certificate SHA-256 digests from `PackageManager` | 90 | 95 |
| `android.integrity.package_id` | Running package name compared to `expectedPackageId` | 85 | 90 |
| `android.store.installer` | `getInstallSourceInfo()` installer package | 25 | 45 |
| `android.integrity.apk_checksum` | `PackageManager.requestChecksums` (API 31+) | 85 | 90 |
| `android.integrity.native_lib_checksum` | SHA-256 of the loaded ABI's `libmobshieldcore.so` | 80 | 85 |
| `android.integrity.check_unavailable` | A configured check timed out, failed, or could not read its input | 30 | 40 |

`android.store.installer` is informational (`UNOFFICIAL_STORE`). `android.integrity.check_unavailable`
scores LOW on its own; one signal is emitted per scan, and its `checks` evidence lists each
`check:reason` pair (for example `apk_checksum:timeout`). Other integrity signals are high weight.

Checks run only when their anchor is configured. The installer check always runs.

## Checks

### SignatureCheck.kt

`PackageManager.GET_SIGNING_CERTIFICATES` with `SigningInfo.apkContentsSigners`. Compares digests to `MobShieldConfig.expectedSigners`. Skipped when the allowlist is empty. Always
reads the running package.

### PackageIdCheck.kt

Compares the running package name to `MobShieldConfig.expectedPackageId`. Skipped when it is not
set. Build variants with an `applicationIdSuffix` report a different package name, so set the anchor
for the variant you ship.

### InstallerOriginCheck.kt

Uses `PackageManager.getInstallSourceInfo()` (API 30+) and compares `installingPackageName` to `MobShieldConfig.allowedInstallSources` (defaults include Play Store IDs).

### ApkChecksumCheck.kt

On Android 12+, calls `requestChecksums` with `TYPE_WHOLE_SHA256` and compares to `MobShieldConfig.expectedApkSha256`.
The digest is computed once per process. If the platform does not return it in time, the check reports
`apk_checksum:unavailable` or `apk_checksum:timeout` through `android.integrity.check_unavailable`.

### NativeLibChecksumCheck.kt

Hashes `libmobshieldcore.so` with SHA-256 where the platform loads it from: the extracted file in
`nativeLibraryDir`, or `lib/<abi>/libmobshieldcore.so` inside the base or split APK when native
libraries are not extracted (the default for current Android Gradle Plugin builds). The ABI is the
first one in the device's preference order that the app ships the library for.

The expected digest is `MobShieldConfig.expectedNativeLibSha256ByAbi[abi]`, falling back to
`expectedNativeLibSha256`. Each ABI ships a different library, so set one digest per ABI you ship.
If the library cannot be found or read, the check reports `native_lib_checksum:missing_file` or
`native_lib_checksum:unreadable` through `android.integrity.check_unavailable`.

## Timeouts

Each check runs on the I/O dispatcher with a timeout: `scanTimeoutMs` (default 500 ms) for the
signature, package name and installer checks, and `digestTimeoutMs` (default 5 s) for the two
checksum checks. A check that times out or throws is reported as `check:timeout` or `check:error`
through `android.integrity.check_unavailable`.

## Configuration

```kotlin
MobShieldConfig.builder()
    .expectedSigners(listOf("...64-char-sha256..."))
    .expectedPackageId("com.example.app")
    .expectedApkSha256("...optional...")
    .expectedNativeLibSha256ByAbi(
        mapOf(
            "arm64-v8a" to "...64-char-sha256...",
            "armeabi-v7a" to "...64-char-sha256...",
        ),
    )
    .allowedInstallSources(setOf("com.android.vending"))
    .build()
```

## Registration

```kotlin
IntegrityDetectionRegistrar.register(context, mobShieldConfig)
```

Module name: `integrity`. Module criticality: `100`.
