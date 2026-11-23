# Android Integrity Detection (mobshield-detect-integrity)

Kotlin-only module for package signature, package name, install source, APK checksum, and native library checksum verification. Signals map to `APP_INTEGRITY` and `UNOFFICIAL_STORE` (MASVS-RES-2).

## Signal catalog

| Signal | Technique | Default weight | Default confidence |
|--------|-----------|----------------|------------------|
| `android.integrity.signature` | Signing certificate SHA-256 digests from `PackageManager` and the APK signing block | 90 | 95 |
| `android.integrity.apk_path` | `ApplicationInfo.sourceDir` compared to the app's mapped `base.apk` | 70 | 80 |
| `android.integrity.package_id` | Running package name compared to `expectedPackageId` | 85 | 90 |
| `android.store.installer` | `getInstallSourceInfo()` installing and initiating packages | 25 | 45 |
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

It also reads the signer certificates from the APK Signature Scheme v2/v3/v3.1 block of
`ApplicationInfo.sourceDir` and compares them to the same allowlist (`reason=apk_signer_mismatch`).
Only the scheme the platform verifies at the device's API level is used, including signers' SDK
ranges and the v3 key rotation lineage, so a rotated key matches when its original certificate is
in `expectedSigners`. APKs signed with v1 only are checked through `PackageManager` alone.

### ApkPathCheck.kt

Runs with the signature check. Reports `android.integrity.apk_path` when `/proc/self/maps` shows
the app's own `base.apk` (in a directory named after the package) and `ApplicationInfo.sourceDir`
is a different path. Skipped when no such mapping is found.

### PackageIdCheck.kt

Compares the running package name to `MobShieldConfig.expectedPackageId`. Skipped when it is not
set. Build variants with an `applicationIdSuffix` report a different package name, so set the anchor
for the variant you ship.

### InstallerOriginCheck.kt

Uses `PackageManager.getInstallSourceInfo()` (API 30+) and compares `installingPackageName` to `MobShieldConfig.allowedInstallSources` (defaults include Play Store IDs).
On API 30+ it also reads `initiatingPackageName`, the app that started the install. When the
installer is allowed but a different, non-allowed app started the install, the signal fires with
an `initiating` evidence entry.

### ApkChecksumCheck.kt

On Android 12+, calls `requestChecksums` with `TYPE_WHOLE_SHA256` and compares to `MobShieldConfig.expectedApkSha256`.
The digest is computed once per process.

`expectedApkSha256` only suits APKs you distribute yourself. Play builds the APKs it installs from
your app bundle and signs them, so their digest is not known at build time and differs per device
configuration. For Play distribution, rely on `expectedSigners` (with your Play app signing
certificate) instead. If the platform does not return it in time, the check reports
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
