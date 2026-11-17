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

/**
 * A serializable snapshot of the current posture, intended to be sent to a backend for server-side
 * decisioning. Client-side termination is bypassable, so the authoritative decision belongs on a
 * server that receives and verifies this report. See `docs/report-attestation.md`.
 */
data class ThreatReport(
    val schemaVersion: String,
    val signalSetVersion: String,
    val buildId: String,
    /** Client clock at the last scan. Informational only: the client controls it. */
    val generatedAtMs: Long,
    val riskLevel: RiskLevel,
    val threats: List<Entry>,
    /**
     * The server-issued challenge this report answers, Base64 (RFC 4648, padded). A server accepts a
     * report only for a challenge it issued, has not seen answered before, and has not expired. Null
     * for reports that were not requested with a challenge; such reports can be replayed.
     */
    val challenge: String? = null,
) {
    data class Entry(
        val type: ThreatType,
        val severity: Severity,
        val score: Int,
        val signals: List<String>,
    )

    companion object {
        /** `report-2` adds the optional `challenge` field to `report-1`. */
        const val CURRENT_SCHEMA_VERSION = "report-2"
    }
}

/**
 * A [ThreatReport] serialized to canonical JSON together with an HMAC-SHA256 signature over exactly
 * those bytes.
 *
 * The HMAC key has to ship inside the app, so anyone who can read or hook the app can sign any
 * report with it. This proves only that the report was not changed in transit; it does not prove
 * which app or device produced it. Use [AttestedThreatReport] instead.
 */
data class SignedThreatReport(
    /** Canonical JSON of the report — the exact string the signature covers (UTF-8). */
    val json: String,
    /** Lowercase hex HMAC-SHA256 of [json]. */
    val signatureHex: String,
)

/**
 * A [ThreatReport] that answers a server challenge, signed by a fresh hardware-backed key whose
 * Android Key Attestation certificate chain is bound to the same challenge.
 *
 * Send all three fields to your backend. The backend verifies the chain against Google's attestation
 * roots, checks the attested challenge, app identity and device state, and then checks [signature]
 * over [json] with the key in the first certificate. See `docs/report-attestation.md`.
 */
data class AttestedThreatReport(
    /** Canonical JSON of the report — the exact string the signature covers (UTF-8). */
    val json: String,
    /** Base64 DER ECDSA (P-256, SHA-256) signature over the UTF-8 bytes of [json]. */
    val signature: String,
    /** Base64 DER X.509 certificates, leaf (the signing key) first, root last. */
    val certificateChain: List<String>,
)
