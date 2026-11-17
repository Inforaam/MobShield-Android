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
 * Standard padded Base64 (RFC 4648 section 4). `java.util.Base64` needs API 26 and
 * `android.util.Base64` is not available in JVM unit tests, so the core encodes by hand.
 */
internal object Base64Codec {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    private const val SIX_BITS = 0x3F

    fun encode(bytes: ByteArray): String {
        val out = StringBuilder((bytes.size + 2) / 3 * 4)
        var i = 0
        while (i < bytes.size) {
            val b0 = bytes[i].toInt() and 0xFF
            val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else 0
            val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xFF else 0
            val triple = (b0 shl 16) or (b1 shl 8) or b2
            out.append(ALPHABET[(triple shr 18) and SIX_BITS])
            out.append(ALPHABET[(triple shr 12) and SIX_BITS])
            out.append(if (i + 1 < bytes.size) ALPHABET[(triple shr 6) and SIX_BITS] else '=')
            out.append(if (i + 2 < bytes.size) ALPHABET[triple and SIX_BITS] else '=')
            i += 3
        }
        return out.toString()
    }
}
