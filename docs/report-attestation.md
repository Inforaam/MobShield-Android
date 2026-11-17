# Verifying reports on your server

MobShield's report tells your backend what the app saw on the device. This page covers how to make
that report something a server can check, what the server must verify, and what a verified report
still cannot tell you.

## Why the HMAC-signed report is deprecated

`MobShield.currentSignedReport(key)` signs the report with HMAC-SHA256 under a key the app supplies.
That key has to ship inside the app, so anyone who can unpack or hook the app has it and can sign a
clean report for any device. The report also had no server challenge, and its timestamp comes from
the client, so a clean report captured once could be sent again forever. The signature only showed
that the report was not changed in transit.

`currentSignedReport` and `MobShieldReporter.sign` still work but are deprecated. Use one of the two
flows below.

## The flow

1. **Your server issues a challenge.** 16 to 128 random bytes (32 is a good size) from a secure
   random generator, stored server-side with a short expiry (a minute or two) and bound to the
   session or user that asked for it.
2. **The app builds a report that carries the challenge** and has it vouched for by the platform,
   using Key Attestation or Play Integrity (below).
3. **Your server verifies it**, and accepts the challenge **once**: delete it as soon as a report
   answers it, and reject reports for challenges that are unknown, expired, already used, or issued
   to a different session.

The challenge is in the report's canonical JSON (`"challenge"`, Base64), and the JSON is what gets
signed, so a report cannot be moved to another challenge. Ignore `generatedAtMs` for freshness: the
client sets it. Use the time your server issued the challenge instead.

## Option A: Key Attestation

Works without Google Play services and needs no Google API on your server.

```kotlin
// Off the main thread: creating a hardware-backed key can take seconds.
val challenge: ByteArray = api.fetchReportChallenge()
val report: AttestedThreatReport = withContext(Dispatchers.IO) {
    MobShield.currentAttestedReport(challenge)
}
api.sendReport(report.json, report.signature, report.certificateChain)
```

For each report, `AndroidKeystoreReportAttester` creates a new EC P-256 key in the Android Keystore
(StrongBox when the device has one, otherwise the TEE) with the challenge as its attestation
challenge, signs the report's canonical JSON with it, returns the key's certificate chain, and deletes
the key. It throws `ReportAttestationException` if the device cannot create or use an attested key.

The server checks, in this order:

1. **The chain.** Each certificate is signed by the next, the root is one of
   [Google's attestation roots](https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate),
   and no certificate is on the
   [revocation status list](https://android.googleapis.com/attestation/status). Use Google's
   [key attestation verification library](https://github.com/android/keyattestation) rather than
   writing your own parser; it handles certificate expiry and other cases custom verifiers miss.
2. **The attestation record** (extension `1.3.6.1.4.1.11129.2.1.17`, read from the certificate
   closest to the root that has it, not blindly from the leaf):
   - `attestationChallenge` equals the challenge you issued.
   - `attestationSecurityLevel` is `TrustedEnvironment` or `StrongBox`, never `Software`. Emulators
     and devices without hardware attestation produce `Software` records with a non-Google root.
   - `attestationApplicationId` names your package and your app signing certificate's SHA-256 digest.
   - `rootOfTrust` meets your policy, for example `verifiedBootState` is `Verified` and
     `deviceLocked` is true. A device with an unlocked bootloader, which most root methods need,
     shows up here, from hardware, whatever the app reports.
3. **The signature.** `signature` (Base64 DER ECDSA with SHA-256) verifies over the UTF-8 bytes of
   `json` with the public key of the first certificate in `certificateChain`.
4. **The challenge in `json`** equals the one you issued, then mark that challenge used.

Only after all of this, read the report's `threats` and `riskLevel`.

## Option B: Play Integrity

If you already use the Play Integrity API, bind its verdict to the report instead:

```kotlin
val challenge: ByteArray = api.fetchReportChallenge()
val json = MobShieldReporter.canonicalJson(MobShield.currentReport(challenge))
// integrityTokenProvider comes from StandardIntegrityManager.prepareIntegrityToken(...).
val token = integrityTokenProvider.request(
    StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
        .setRequestHash(MobShieldReporter.requestHash(json))
        .build(),
).await().token() // await() from kotlinx-coroutines-play-services
api.sendReport(json, token)
```

The server decodes the token with Google's `decodeIntegrityToken` endpoint, checks that
`requestDetails.requestHash` equals the lowercase hex SHA-256 of the `json` it received, checks
`appIntegrity` and `deviceIntegrity` against your policy, checks the challenge in `json` as in the
flow above, and only then reads the report. MobShield does not depend on the Play Integrity library;
add it to your app if you use this option.

## What a verified report proves, and what it does not

A verified report proves that it was produced **for your challenge**, **once**, by **your app**
(package and signing certificate), on a device whose **hardware** vouched for it, and that it was not
changed afterwards.

It does not prove that the report's **contents** are true. The app builds the report, and on a device
where an attacker can hook the app, the attacker can hand a clean report to the attested key or to
Play Integrity, which will vouch for it. No client-side signing scheme can prevent that. Therefore:

- Base decisions on what the **platform** attests: the boot state and security level in the
  attestation record, or Play Integrity's device and app verdicts. Those come from hardware or from
  Google, not from app code.
- Treat MobShield's `threats` as additional context: a report of a hook is strong evidence, but the
  absence of one is not proof that there is none.
- Key attestation can be defeated by leaked attestation keys, which is why the revocation list check
  matters, and why devices that launched with Android 16 or later use Remote Key Provisioning.

## Changes in this version

- New `MobShield.currentAttestedReport(challenge)`, `MobShieldReporter.attest`, `ReportAttester` and
  `AndroidKeystoreReportAttester`, `AttestedThreatReport`, and `ReportAttestationException`.
- New `MobShield.currentReport(challenge)` and `MobShieldReporter.requestHash(json)` for Play
  Integrity.
- Reports gain an optional `challenge` field; the schema version is now `report-2`. Reports built
  without a challenge are unchanged apart from the version.
- `currentSignedReport`, `MobShieldReporter.sign` and HMAC signing are deprecated.
