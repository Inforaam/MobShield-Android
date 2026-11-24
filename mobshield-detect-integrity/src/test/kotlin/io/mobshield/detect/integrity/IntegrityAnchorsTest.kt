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

import io.mobshield.core.MobShieldConfig
import io.mobshield.detect.integrity.internal.DigestUtil
import io.mobshield.detect.integrity.internal.NativeLibraryLocator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class IntegrityAnchorsTest {
    @get:Rule
    val temp = TemporaryFolder()

    private val lib = NativeLibChecksumCheck.CORE_LIBRARY_NAME
    private val digest = "a".repeat(64)

    private fun apk(
        name: String,
        entries: Map<String, ByteArray>,
    ): File {
        val file = temp.newFile(name)
        ZipOutputStream(file.outputStream()).use { zip ->
            entries.forEach { (entry, bytes) ->
                zip.putNextEntry(ZipEntry(entry))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return file
    }

    private fun sha256(bytes: ByteArray) = bytes.inputStream().use(DigestUtil::sha256HexStream)

    @Test
    fun digestsByAbi_coversEveryAbiInBaseAndSplits() {
        val arm64 = byteArrayOf(1)
        val arm = byteArrayOf(2)
        val base = apk("base.apk", mapOf("lib/arm64-v8a/$lib" to arm64, "lib/arm64-v8a/libother.so" to byteArrayOf(9)))
        val split = apk("split.apk", mapOf("lib/armeabi-v7a/$lib" to arm))
        assertEquals(
            mapOf("arm64-v8a" to sha256(arm64), "armeabi-v7a" to sha256(arm)),
            NativeLibraryLocator.digestsByAbi(lib, listOf(base.path, split.path)),
        )
    }

    @Test
    fun configSnippet_listsTheValues() {
        val anchors =
            IntegrityAnchors(
                packageName = "com.example.app",
                signerSha256 = listOf(digest),
                nativeLibSha256ByAbi = mapOf("arm64-v8a" to digest),
                installingPackage = "com.android.vending",
            )
        val snippet = anchors.toConfigSnippet()
        assertEquals(
            """
            MobShieldConfig.builder()
                .expectedPackageId("com.example.app")
                .expectedSigners(listOf("$digest"))
                .expectedNativeLibSha256ByAbi(
                    mapOf(
                        "arm64-v8a" to "$digest",
                    ),
                )
                .build()
            """.trimIndent(),
            snippet,
        )
    }

    @Test
    fun configSnippet_valuesAreAcceptedByTheConfig() {
        val config =
            MobShieldConfig
                .builder()
                .expectedPackageId("com.example.app")
                .expectedSigners(listOf(digest))
                .expectedNativeLibSha256ByAbi(mapOf("arm64-v8a" to digest))
                .build()
        assertEquals(digest, config.expectedNativeLibSha256ByAbi["arm64-v8a"])
    }

    @Test
    fun configSnippet_omitsEmptyValues() {
        val snippet = IntegrityAnchors("com.example.app", emptyList(), emptyMap(), null).toConfigSnippet()
        assertFalse(snippet.contains("expectedSigners"))
        assertFalse(snippet.contains("expectedNativeLibSha256ByAbi"))
    }
}
