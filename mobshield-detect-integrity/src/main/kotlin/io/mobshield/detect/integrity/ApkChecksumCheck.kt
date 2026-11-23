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
package io.mobshield.detect.integrity

import android.content.pm.Checksum
import android.content.pm.PackageManager
import android.os.Build
import io.mobshield.detect.integrity.internal.DigestUtil

class ApkChecksumCheck(
    private val expectedApkSha256: String?,
    private val sdkIntProvider: () -> Int = { Build.VERSION.SDK_INT },
    private val checksumProvider: () -> String?,
) {
    fun scan(): ScanHit? {
        val expected = expectedApkSha256 ?: return null
        if (sdkIntProvider() < Build.VERSION_CODES.S) {
            return null
        }
        val actual = checksumProvider() ?: return ScanHit(expected = expected, actual = null, reason = "unavailable")
        if (DigestUtil.hexMatches(expected, actual)) {
            return null
        }
        return ScanHit(expected = expected, actual = actual, reason = "mismatch")
    }

    data class ScanHit(
        val expected: String,
        val actual: String?,
        val reason: String,
    )

    companion object {
        // TYPE_WHOLE_SHA256 is deprecated because the platform does not enforce it, but it is still
        // computed on request, and it is the plain file SHA-256 that `expectedApkSha256` pins. The
        // Merkle-root checksum types would need a different expected value.
        @Suppress("DEPRECATION")
        fun requestWholeApkSha256(
            packageManager: PackageManager,
            packageName: String,
            timeoutMs: Long = DEFAULT_TIMEOUT_MS,
        ): String? {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
                return null
            }
            val result =
                java.util.concurrent.atomic
                    .AtomicReference<String?>()
            val latch = java.util.concurrent.CountDownLatch(1)
            val listener =
                PackageManager.OnChecksumsReadyListener { checksums ->
                    val digest =
                        checksums
                            .firstOrNull { checksum -> checksum.type == Checksum.TYPE_WHOLE_SHA256 }
                            ?.value
                    result.set(digest?.let { DigestUtil.bytesToHex(it) })
                    latch.countDown()
                }
            try {
                packageManager.requestChecksums(
                    packageName,
                    false,
                    Checksum.TYPE_WHOLE_SHA256,
                    emptyList(),
                    listener,
                )
                if (!latch.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                    return null
                }
            } catch (_: Exception) {
                return null
            }
            return result.get()
        }

        const val DEFAULT_TIMEOUT_MS = 5_000L
    }
}
