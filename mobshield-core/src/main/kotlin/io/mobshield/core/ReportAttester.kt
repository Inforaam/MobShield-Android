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
 * Signs a report payload with a key whose attestation is bound to a server challenge.
 *
 * [AndroidKeystoreReportAttester] is the implementation to use in apps. The interface exists so the
 * reporting path can be tested on the JVM, where the Android Keystore is not available.
 */
fun interface ReportAttester {
    /**
     * Signs [payload] with a key attested for [challenge].
     *
     * @throws ReportAttestationException if the key cannot be created, attested or used.
     */
    fun attest(
        challenge: ByteArray,
        payload: ByteArray,
    ): Attestation

    /** The signature over the payload and the DER certificate chain of the signing key, leaf first. */
    class Attestation(
        val signature: ByteArray,
        val certificateChain: List<ByteArray>,
    )
}

/** The device could not create, attest or use a signing key for a report. */
class ReportAttestationException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)
