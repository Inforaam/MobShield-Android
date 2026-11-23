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

import io.mobshield.detect.integrity.NativeLibChecksumCheck.NativeLibrary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class NativeLibChecksumCheckTest {
    private val digest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    private val arm64Digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    private val other = "abababababababababababababababababababababababababababababababab"

    private fun library(abi: String? = "arm64-v8a") =
        NativeLibrary(abi = abi, path = "base.apk!/lib") { error("unused") }

    @Test
    fun scan_notConfigured_doesNotLookForTheLibrary() {
        val check =
            NativeLibChecksumCheck(
                expectedNativeLibSha256 = null,
                libraryProvider = { error("must not be called") },
            )
        assertNull(check.scan())
    }

    @Test
    fun scan_matchingDigest_returnsNull() {
        val check =
            NativeLibChecksumCheck(
                expectedNativeLibSha256 = digest,
                libraryProvider = { library() },
                digestComputer = { digest },
            )
        assertNull(check.scan())
    }

    @Test
    fun scan_mismatch_reportsPathAndAbi() {
        val check =
            NativeLibChecksumCheck(
                expectedNativeLibSha256 = digest,
                libraryProvider = { library() },
                digestComputer = { other },
            )
        val hit = check.scan()
        assertEquals("mismatch", hit?.reason)
        assertEquals("arm64-v8a", hit?.abi)
        assertEquals("base.apk!/lib", hit?.path)
    }

    @Test
    fun scan_prefersTheDigestForTheLoadedAbi() {
        val check =
            NativeLibChecksumCheck(
                expectedNativeLibSha256 = digest,
                expectedByAbi = mapOf("arm64-v8a" to arm64Digest),
                libraryProvider = { library() },
                digestComputer = { arm64Digest },
            )
        assertNull(check.scan())
    }

    @Test
    fun scan_fallsBackToTheSingleDigestForOtherAbis() {
        val check =
            NativeLibChecksumCheck(
                expectedNativeLibSha256 = digest,
                expectedByAbi = mapOf("x86_64" to arm64Digest),
                libraryProvider = { library() },
                digestComputer = { other },
            )
        assertEquals(digest, check.scan()?.expected)
    }

    @Test
    fun scan_abiWithoutAnyExpectedDigest_isSkipped() {
        val check =
            NativeLibChecksumCheck(
                expectedNativeLibSha256 = null,
                expectedByAbi = mapOf("x86_64" to arm64Digest),
                libraryProvider = { library() },
                digestComputer = { other },
            )
        assertNull(check.scan())
    }

    @Test
    fun scan_libraryNotFound_reportsMissingFile() {
        val check = NativeLibChecksumCheck(expectedNativeLibSha256 = digest, libraryProvider = { null })
        assertEquals("missing_file", check.scan()?.reason)
    }

    @Test
    fun scan_unreadable_reportsUnreadable() {
        val check =
            NativeLibChecksumCheck(
                expectedNativeLibSha256 = digest,
                libraryProvider = { library() },
                digestComputer = { null },
            )
        assertEquals("unreadable", check.scan()?.reason)
    }
}
