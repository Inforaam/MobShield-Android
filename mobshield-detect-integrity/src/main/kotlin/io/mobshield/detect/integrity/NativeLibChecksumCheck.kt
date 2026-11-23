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

import io.mobshield.detect.integrity.internal.DigestUtil
import java.io.InputStream

class NativeLibChecksumCheck(
    private val expectedNativeLibSha256: String?,
    private val expectedByAbi: Map<String, String> = emptyMap(),
    private val libraryProvider: () -> NativeLibrary?,
    private val digestComputer: (NativeLibrary) -> String? = { library ->
        runCatching { library.open().use(DigestUtil::sha256HexStream) }.getOrNull()
    },
) {
    fun scan(): ScanHit? {
        if (expectedNativeLibSha256 == null && expectedByAbi.isEmpty()) {
            return null
        }
        val library =
            libraryProvider()
                ?: return ScanHit(expected = expectedNativeLibSha256, actual = null, reason = "missing_file")
        val expected = library.abi?.let(expectedByAbi::get) ?: expectedNativeLibSha256 ?: return null
        val actual =
            digestComputer(library)
                ?: return ScanHit(expected = expected, actual = null, reason = "unreadable", path = library.path)
        if (DigestUtil.hexMatches(expected, actual)) {
            return null
        }
        return ScanHit(
            expected = expected,
            actual = actual,
            reason = "mismatch",
            path = library.path,
            abi = library.abi,
        )
    }

    /** A native library extracted on disk or stored inside an APK. [path] is used as evidence only. */
    class NativeLibrary(
        val abi: String?,
        val path: String,
        val open: () -> InputStream,
    )

    data class ScanHit(
        val expected: String?,
        val actual: String?,
        val reason: String,
        val path: String? = null,
        val abi: String? = null,
    )

    companion object {
        const val CORE_LIBRARY_NAME = "libmobshieldcore.so"
    }
}
