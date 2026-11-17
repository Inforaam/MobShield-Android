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

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.security.KeyStore
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Runs the real Keystore attester. On an emulator the chain is software-rooted, which a server must
 * reject, but the structure is the same: the leaf carries the Key Attestation extension containing
 * the challenge, and its key verifies the signature.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKeystoreReportAttesterInstrumentedTest {
    private val challenge = ByteArray(32) { (it * 7).toByte() }
    private val payload = "{\"challenge\":\"test\"}".toByteArray()

    @Test
    fun attest_returnsAChainWhoseLeafSignedThePayloadAndCarriesTheChallenge() {
        val attestation = AndroidKeystoreReportAttester(preferStrongBox = false).attest(challenge, payload)

        val certificates = attestation.certificateChain.map(::certificate)
        assertTrue(certificates.size > 1)
        val leaf = certificates.first()

        val extension = leaf.getExtensionValue(KEY_ATTESTATION_OID)
        assertNotNull(extension)
        assertTrue(contains(extension!!, challenge))

        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(leaf.publicKey)
        verifier.update(payload)
        assertTrue(verifier.verify(attestation.signature))
    }

    @Test
    fun attest_deletesTheKeyAfterwards() {
        AndroidKeystoreReportAttester(preferStrongBox = false).attest(challenge, payload)

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(keyStore.aliases().toList().any { it.startsWith("io.mobshield.report.") })
    }

    private fun certificate(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    private fun contains(
        haystack: ByteArray,
        needle: ByteArray,
    ): Boolean =
        (0..haystack.size - needle.size).any { start ->
            needle.indices.all { haystack[start + it] == needle[it] }
        }

    private companion object {
        const val KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
    }
}
