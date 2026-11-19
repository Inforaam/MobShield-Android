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

package io.mobshield.gradle.internal

import java.security.MessageDigest
import java.security.SecureRandom

internal object CryptoUtils {
    fun randomBytes(length: Int): ByteArray {
        val bytes = ByteArray(length)
        SecureRandom().nextBytes(bytes)
        return bytes
    }

    /** First [length] bytes (at most 32) of SHA-256 over [label], a zero byte and [seed]. */
    fun deriveBytes(seed: ByteArray, label: String, length: Int): ByteArray {
        require(length in 1..32) { "length must be 1 to 32" }
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(label.toByteArray())
        digest.update(0)
        digest.update(seed)
        return digest.digest().copyOf(length)
    }

    fun sha256Hex(data: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(data).toHex()

    fun normalizeSha256(input: String): String = input.replace(":", "").lowercase()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
