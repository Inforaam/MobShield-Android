/*
 * Copyright 2025 MobShield Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.mobshield.core

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Builds and signs [ThreatReport]s. It never performs networking: the host app fetches challenges
 * from, and sends reports to, its own backend. See `docs/report-attestation.md`.
 */
object MobShieldReporter {
    private const val HMAC_ALGORITHM = "HmacSHA256"

    /** Shortest server challenge accepted, in bytes. */
    const val MIN_CHALLENGE_BYTES = 16

    /** Longest server challenge accepted, in bytes (the Android Key Attestation limit). */
    const val MAX_CHALLENGE_BYTES = 128

    /**
     * Builds a report from a posture snapshot and the events of the last scan wave.
     *
     * @param challenge the server-issued challenge this report answers, [MIN_CHALLENGE_BYTES] to
     *   [MAX_CHALLENGE_BYTES] random bytes. Without one, a captured report can be replayed.
     */
    fun makeReport(
        state: MobShieldState,
        events: List<ThreatEvent>,
        buildId: String,
        schemaVersion: String = ThreatReport.CURRENT_SCHEMA_VERSION,
        challenge: ByteArray? = null,
    ): ThreatReport {
        challenge?.let(::requireValidChallenge)
        val entries =
            events
                .sortedByDescending { it.score }
                .map { event ->
                    ThreatReport.Entry(
                        type = event.type,
                        severity = event.severity,
                        score = event.score,
                        signals = event.signals,
                    )
                }
        return ThreatReport(
            schemaVersion = schemaVersion,
            signalSetVersion = state.signalSetVersion,
            buildId = buildId,
            generatedAtMs = state.lastScanMs,
            riskLevel = state.riskLevel,
            threats = entries,
            challenge = challenge?.let(Base64Codec::encode),
        )
    }

    /**
     * Encodes a report to canonical (deterministic, sorted-key) JSON so a backend can recompute the
     * signature over an identical string. Built by hand to avoid Android-only JSON that is
     * unavailable in JVM unit tests.
     */
    fun canonicalJson(report: ThreatReport): String {
        val threats =
            report.threats.joinToString(prefix = "[", postfix = "]") { entry ->
                buildString {
                    append('{')
                    append("\"score\":").append(entry.score).append(',')
                    append("\"severity\":").append(quote(entry.severity.name)).append(',')
                    append("\"signals\":")
                    append(entry.signals.joinToString(prefix = "[", postfix = "]") { quote(it) })
                    append(',')
                    append("\"type\":").append(quote(entry.type.name))
                    append('}')
                }
            }
        return buildString {
            append('{')
            append("\"buildId\":").append(quote(report.buildId)).append(',')
            report.challenge?.let { append("\"challenge\":").append(quote(it)).append(',') }
            append("\"generatedAtMs\":").append(report.generatedAtMs).append(',')
            append("\"riskLevel\":").append(quote(report.riskLevel.name)).append(',')
            append("\"schemaVersion\":").append(quote(report.schemaVersion)).append(',')
            append("\"signalSetVersion\":").append(quote(report.signalSetVersion)).append(',')
            append("\"threats\":").append(threats)
            append('}')
        }
    }

    /**
     * Signs [report], which must carry [challenge], with a key attested for the same challenge.
     *
     * With the default [AndroidKeystoreReportAttester] this creates a hardware-backed key, which can
     * take seconds: do not call it on the main thread.
     *
     * @throws IllegalArgumentException if [report] does not carry [challenge].
     * @throws ReportAttestationException if the device cannot create or use an attested key.
     */
    fun attest(
        report: ThreatReport,
        challenge: ByteArray,
        attester: ReportAttester = AndroidKeystoreReportAttester(),
    ): AttestedThreatReport {
        requireValidChallenge(challenge)
        require(report.challenge == Base64Codec.encode(challenge)) {
            "The report must carry the challenge it is attested for; build it with makeReport(challenge = ...)"
        }
        val json = canonicalJson(report)
        val attestation = attester.attest(challenge, json.toByteArray(Charsets.UTF_8))
        return AttestedThreatReport(
            json = json,
            signature = Base64Codec.encode(attestation.signature),
            certificateChain = attestation.certificateChain.map(Base64Codec::encode),
        )
    }

    /**
     * Lowercase hex SHA-256 of the UTF-8 bytes of [json]. Pass it as the `requestHash` of a Play
     * Integrity standard request to bind the integrity verdict to a report that carries a challenge;
     * the server then checks that the verdict's `requestHash` matches the report it received.
     */
    fun requestHash(json: String): String =
        MessageDigest.getInstance("SHA-256").digest(json.toByteArray(Charsets.UTF_8)).toHex()

    /**
     * Produces the canonical JSON and its HMAC-SHA256 signature under [key].
     *
     * The key ships inside the app, so anyone who can read or hook the app can sign a clean report
     * with it, and a report without a challenge can be replayed. The signature shows only that the
     * report was not changed in transit.
     */
    @Deprecated(
        "An HMAC key shipped in the app cannot prove where a report came from. " +
            "Use attest() with a server challenge; see docs/report-attestation.md.",
        ReplaceWith("attest(report, challenge)"),
    )
    fun sign(
        report: ThreatReport,
        key: ByteArray,
    ): SignedThreatReport {
        val json = canonicalJson(report)
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(key, HMAC_ALGORITHM))
        val signature = mac.doFinal(json.toByteArray(Charsets.UTF_8))
        return SignedThreatReport(json = json, signatureHex = signature.toHex())
    }

    private fun requireValidChallenge(challenge: ByteArray) {
        require(challenge.size in MIN_CHALLENGE_BYTES..MAX_CHALLENGE_BYTES) {
            "A challenge must be $MIN_CHALLENGE_BYTES to $MAX_CHALLENGE_BYTES bytes; got ${challenge.size}"
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun quote(value: String): String {
        val sb = StringBuilder(value.length + 2)
        sb.append('"')
        for (ch in value) {
            when (ch) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else ->
                    if (ch < ' ') {
                        sb.append("\\u").append("%04x".format(ch.code))
                    } else {
                        sb.append(ch)
                    }
            }
        }
        sb.append('"')
        return sb.toString()
    }
}
