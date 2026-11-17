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

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * Signs reports with a new Android Keystore key for every report, created with the server's
 * challenge as its attestation challenge, and deletes the key afterwards.
 *
 * The key's certificate chain is an Android Key Attestation chain. On a device with hardware-backed
 * attestation it chains to a Google root and records, in hardware, the challenge, the app's package
 * name and signing certificate, and the device's verified boot state. Emulators and devices without
 * hardware attestation produce a software-rooted chain that a server must reject.
 *
 * Creating an attested key takes from tens of milliseconds to a few seconds (StrongBox is the slow
 * case), so call [attest] off the main thread, and request reports per session or per sensitive
 * action rather than per network call.
 *
 * @param preferStrongBox create the key in StrongBox when the device has one (API 28+), falling back
 *   to the TEE otherwise.
 */
class AndroidKeystoreReportAttester(
    private val preferStrongBox: Boolean = true,
) : ReportAttester {
    override fun attest(
        challenge: ByteArray,
        payload: ByteArray,
    ): ReportAttester.Attestation {
        val alias = ALIAS_PREFIX + UUID.randomUUID()
        try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            try {
                generateKey(alias, challenge)
                val chain =
                    keyStore.getCertificateChain(alias)
                        ?: throw ReportAttestationException("The Keystore returned no certificate chain")
                val privateKey =
                    keyStore.getKey(alias, null) as? PrivateKey
                        ?: throw ReportAttestationException("The Keystore returned no private key")
                val signature =
                    Signature.getInstance(SIGNATURE_ALGORITHM).run {
                        initSign(privateKey)
                        update(payload)
                        sign()
                    }
                return ReportAttester.Attestation(signature, chain.map { it.encoded })
            } finally {
                keyStore.deleteEntry(alias)
            }
        } catch (e: GeneralSecurityException) {
            throw ReportAttestationException("Could not create or use an attested key", e)
        } catch (e: ProviderException) {
            throw ReportAttestationException("Could not create or use an attested key", e)
        } catch (e: IOException) {
            throw ReportAttestationException("Could not open the Android Keystore", e)
        }
    }

    private fun generateKey(
        alias: String,
        challenge: ByteArray,
    ) {
        if (preferStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generateKey(alias, challenge, strongBox = true)
                return
            } catch (ignored: StrongBoxUnavailableException) {
                // No StrongBox on this device; the TEE key below is attested the same way.
            }
        }
        generateKey(alias, challenge, strongBox = false)
    }

    private fun generateKey(
        alias: String,
        challenge: ByteArray,
        strongBox: Boolean,
    ) {
        val spec =
            KeyGenParameterSpec
                .Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec(CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .apply {
                    if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(true)
                }.build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS_PREFIX = "io.mobshield.report."
        const val CURVE = "secp256r1"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    }
}
