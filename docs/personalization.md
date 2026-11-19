# Build personalization

This page covers what the `io.mobshield.personalize` Gradle plugin does, when it has any effect, and
why it keeps no secrets.

## What it does

The plugin generates `mobshield_buildinfo.h` for MobShield's native code. The header sets:

- `MOBSHIELD_BUILD_ID`: `android-` followed by 16 hex characters derived from a random per-build seed
  (or from `randomSeed`, if you set it). `MobShield.getBuildId()` returns it, and reports carry it as
  `buildId`. It is a **public identifier**, safe to log, used to tell builds apart in reports.
- `MOBSHIELD_EXPECTED_SIGNER_SHA256`, `MOBSHIELD_EXPECTED_PACKAGE` and
  `MOBSHIELD_AGGRESSIVE_ANTI_DEBUG`, from the `mobshield { }` block. The native code does not read
  these yet; the runtime integrity checks use the values you pass to `MobShieldConfig`.

`mobshieldVerify` runs after `assemble`. It checks the APK's signing certificate against
`expectedSigningCertSha256`, and checks that `libmobshieldcore.so` contains
`MOBSHIELD_BUILD_ID=<this build's ID>`, which shows the library was compiled with this build's header.

## It only applies when MobShield is compiled in your build

The plugin passes the generated header to MobShield's native modules (the `:mobshield*` projects)
in the same Gradle build. It cannot change native libraries that are already compiled.

Apps that depend on MobShield from **Maven Central or JitPack** get prebuilt native libraries, so the
plugin has no effect on them. Those libraries are the same in every app that uses the same MobShield
release, and `getBuildId()` returns the release's build ID. The plugin is also not published to Maven
Central. In practice, personalization only affects builds that include MobShield's source, such as
this repository's sample app.

## One bypass fits every app on the same release

Because the shipped binaries are identical, a hook script or patch that defeats a MobShield release
works against every app using that release. Changing a few constants per build would not change that
much: bypass tools target function names, behaviour and code patterns, not constants.

Plan for it:

- Make decisions that matter on your server, from attested reports
  ([report-attestation.md](report-attestation.md)), not from the client's word.
- Treat termination as a deterrent ([termination.md](termination.md)).

## There are no secrets in the app

Anything that ships in an app can be read by whoever has the app. MobShield therefore generates
nothing that is meant to stay secret, and the header and the binary contain no keys.

Earlier versions were designed otherwise:

- The plugin derived 16 bytes of "build entropy" and used them as an AES-GCM key and as an HMAC key.
- The native core was meant to embed the same bytes in `libmobshieldcore.so` behind a searchable
  `MOBSHIELD_ENTROPY=` marker and return them from `getBuildId()`, which would have put them in every
  report's `buildId`.
- The encrypted data was 64 bytes of `0xFF`, and no native code read it. The native-library HMAC and
  the symbol-rename macros were not used by any native code either.

The "encryption" protected nothing, and calling the key a build ID would have invited apps to log it.
All of it has been removed.

In practice the generated header never reached the native code. A checked-in stub
`mobshield_buildinfo.h` sat next to `mobshield_native.cpp`, and a quoted `#include` finds that copy
first. Every build, including source builds with the plugin, shipped the stub's `library-stub` build
ID. So the entropy never ended up in a binary or a report, and per-build personalization never took
effect. The stub now lives in `stub/`, so the generated header is used when Gradle provides one.

The hook module's prologue baselines are separate and are described in
[detection/android-hooks.md](detection/android-hooks.md): no build step fills them in today, so the
check relies on its trampoline heuristic.

## Changes in this version

- `MobShield.getBuildId()` returns the public build ID (`android-<16 hex>` for personalized builds)
  instead of the build entropy.
- The generated header no longer contains `MOBSHIELD_BUILD_ENTROPY`, the AES-GCM nonce and
  ciphertext, the key-derivation salt, `MOBSHIELD_NATIVELIB_HMAC`, or symbol-rename macros.
- The native core embeds `MOBSHIELD_BUILD_ID=<id>` instead of `MOBSHIELD_ENTROPY=<entropy>`, and
  `mobshieldVerify` checks for it.
- The stub header moved to `mobshield-core/src/main/cpp/stub/`, so source builds with the plugin now
  actually compile with the generated header. Builds from this repository, including release builds,
  report a generated `android-…` build ID instead of `library-stub`.
