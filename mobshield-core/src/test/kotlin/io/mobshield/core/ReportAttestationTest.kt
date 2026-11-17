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

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.random.Random

/**
 * Reports answer a server challenge and are signed by a key attested for that challenge. The Android
 * Keystore is not available on the JVM, so these tests sign with a software key in its place; what
 * they check is that the challenge, the signed bytes and the encoding are what a server verifies.
 * See `docs/report-attestation.md`.
 */
class ReportAttestationTest {
    private val challenge = ByteArray(32) { it.toByte() }
    private val otherChallenge = ByteArray(32) { (it + 1).toByte() }
    private val keyPair = ecKeyPair()
    private val fakeChain = listOf(byteArrayOf(1, 2, 3), byteArrayOf(4, 5))

    @Test
    fun makeReport_carriesTheChallenge_inTheSignedJson() {
        val report = report(challenge)
        val json = MobShieldReporter.canonicalJson(report)

        assertEquals(Base64.getEncoder().encodeToString(challenge), report.challenge)
        assertTrue(json.contains("\"challenge\":\"${report.challenge}\""))
        // Sorted keys: buildId < challenge < generatedAtMs.
        assertTrue(json.indexOf("\"buildId\"") < json.indexOf("\"challenge\""))
        assertTrue(json.indexOf("\"challenge\"") < json.indexOf("\"generatedAtMs\""))
    }

    @Test
    fun reportsForDifferentChallenges_differ() {
        val a = MobShieldReporter.canonicalJson(report(challenge))
        val b = MobShieldReporter.canonicalJson(report(otherChallenge))

        assertFalse(a == b)
    }

    @Test
    fun makeReport_withoutChallenge_hasNone() {
        assertNull(report(null).challenge)
    }

    @Test
    fun makeReport_rejectsChallengesOutsideTheAllowedLength() {
        assertThrows(IllegalArgumentException::class.java) { report(ByteArray(15)) }
        assertThrows(IllegalArgumentException::class.java) { report(ByteArray(129)) }
        report(ByteArray(MobShieldReporter.MIN_CHALLENGE_BYTES))
        report(ByteArray(MobShieldReporter.MAX_CHALLENGE_BYTES))
    }

    @Test
    fun attest_signsTheCanonicalJson_withAKeyAttestedForTheChallenge() {
        var seenChallenge: ByteArray? = null
        var seenPayload: ByteArray? = null
        val attester =
            ReportAttester { c, payload ->
                seenChallenge = c
                seenPayload = payload
                ReportAttester.Attestation(sign(payload), fakeChain)
            }

        val attested = MobShieldReporter.attest(report(challenge), challenge, attester)

        assertArrayEquals(challenge, seenChallenge)
        assertArrayEquals(attested.json.toByteArray(Charsets.UTF_8), seenPayload)
        assertTrue(verify(attested.json, attested.signature))
        assertEquals(fakeChain.map { Base64.getEncoder().encodeToString(it) }, attested.certificateChain)
    }

    @Test
    fun attest_signatureDoesNotCoverAChangedReport() {
        val attester = ReportAttester { _, payload -> ReportAttester.Attestation(sign(payload), fakeChain) }
        val attested = MobShieldReporter.attest(report(challenge), challenge, attester)

        val tampered = attested.json.replace("\"HIGH\"", "\"NONE\"")

        assertFalse(tampered == attested.json)
        assertFalse(verify(tampered, attested.signature))
    }

    @Test
    fun attest_requiresTheReportToCarryTheSameChallenge() {
        var called = false
        val attester =
            ReportAttester { _, payload ->
                called = true
                ReportAttester.Attestation(sign(payload), fakeChain)
            }

        assertThrows(IllegalArgumentException::class.java) {
            MobShieldReporter.attest(report(null), challenge, attester)
        }
        assertThrows(IllegalArgumentException::class.java) {
            MobShieldReporter.attest(report(otherChallenge), challenge, attester)
        }
        assertFalse(called)
    }

    @Test
    fun attest_propagatesAttestationFailures() {
        val failure = ReportAttestationException("no attestation")
        val attester = ReportAttester { _, _ -> throw failure }

        val thrown =
            assertThrows(ReportAttestationException::class.java) {
                MobShieldReporter.attest(report(challenge), challenge, attester)
            }
        assertSame(failure, thrown)
    }

    @Test
    fun requestHash_isSha256HexOfTheJson() {
        val json = MobShieldReporter.canonicalJson(report(challenge))
        val expected =
            MessageDigest
                .getInstance("SHA-256")
                .digest(json.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }

        assertEquals(expected, MobShieldReporter.requestHash(json))
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            MobShieldReporter.requestHash("abc"),
        )
    }

    @Test
    fun base64Codec_matchesTheJdkEncoder() {
        val random = Random(42)
        for (size in 0..64) {
            val bytes = random.nextBytes(size)
            assertEquals(Base64.getEncoder().encodeToString(bytes), Base64Codec.encode(bytes))
        }
    }

    private fun report(challenge: ByteArray?): ThreatReport =
        MobShieldReporter.makeReport(
            state =
                MobShieldState(
                    riskLevel = RiskLevel.HIGH,
                    activeThreats = emptyList(),
                    lastScanMs = 1L,
                    signalSetVersion = MobShield.SIGNAL_SET_VERSION,
                    running = true,
                ),
            events = listOf(ThreatEvent.HookFramework(Severity.HIGH, listOf("android.hook.frida_port"), 60, 0L)),
            buildId = "b",
            challenge = challenge,
        )

    private fun sign(payload: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(payload)
            sign()
        }

    private fun verify(
        json: String,
        signatureBase64: String,
    ): Boolean =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(keyPair.public)
            update(json.toByteArray(Charsets.UTF_8))
            verify(Base64.getDecoder().decode(signatureBase64))
        }

    private fun ecKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
}
