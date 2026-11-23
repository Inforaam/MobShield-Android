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
package io.mobshield.detect.integrity.internal

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class NativeLibraryLocatorTest {
    @get:Rule
    val temp = TemporaryFolder()

    private val name = "libmobshieldcore.so"
    private val arm64Bytes = byteArrayOf(1, 2, 3)
    private val armBytes = byteArrayOf(4, 5)

    private fun apk(
        fileName: String,
        entries: Map<String, ByteArray>,
    ): File {
        val file = temp.newFile(fileName)
        ZipOutputStream(file.outputStream()).use { zip ->
            for ((entry, bytes) in entries) {
                zip.putNextEntry(ZipEntry(entry))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return file
    }

    private fun emptyLibDir() = temp.newFolder("lib")

    @Test
    fun locate_readsTheLibraryFromTheApkWhenNotExtracted() {
        val base = apk("base.apk", mapOf("lib/arm64-v8a/$name" to arm64Bytes, "lib/armeabi-v7a/$name" to armBytes))
        val library =
            NativeLibraryLocator.locate(name, emptyLibDir().path, listOf(base.path), listOf("arm64-v8a", "armeabi-v7a"))
        assertEquals("arm64-v8a", library?.abi)
        assertEquals("${base.path}!/lib/arm64-v8a/$name", library?.path)
        assertArrayEquals(arm64Bytes, library?.open()?.use { it.readBytes() })
    }

    @Test
    fun locate_followsDeviceAbiPreference() {
        val base = apk("base.apk", mapOf("lib/arm64-v8a/$name" to arm64Bytes, "lib/armeabi-v7a/$name" to armBytes))
        val library =
            NativeLibraryLocator.locate(name, null, listOf(base.path), listOf("armeabi-v7a", "arm64-v8a"))
        assertEquals("armeabi-v7a", library?.abi)
    }

    @Test
    fun locate_findsTheLibraryInASplitApk() {
        val base = apk("base.apk", mapOf("classes.dex" to byteArrayOf(0)))
        val split = apk("split_config.arm64_v8a.apk", mapOf("lib/arm64-v8a/$name" to arm64Bytes))
        val library =
            NativeLibraryLocator.locate(name, null, listOf(base.path, split.path), listOf("arm64-v8a"))
        assertEquals("${split.path}!/lib/arm64-v8a/$name", library?.path)
    }

    @Test
    fun locate_prefersTheExtractedFile() {
        val base = apk("base.apk", mapOf("lib/arm64-v8a/$name" to arm64Bytes))
        val libDir = emptyLibDir()
        File(libDir, name).writeBytes(byteArrayOf(9))
        val library = NativeLibraryLocator.locate(name, libDir.path, listOf(base.path), listOf("arm64-v8a"))
        assertEquals("arm64-v8a", library?.abi)
        assertEquals(File(libDir, name).absolutePath, library?.path)
        assertArrayEquals(byteArrayOf(9), library?.open()?.use { it.readBytes() })
    }

    @Test
    fun locate_notShippedForAnySupportedAbi_returnsNull() {
        val base = apk("base.apk", mapOf("lib/x86_64/$name" to arm64Bytes))
        assertNull(NativeLibraryLocator.locate(name, emptyLibDir().path, listOf(base.path), listOf("arm64-v8a")))
    }

    @Test
    fun locate_unreadableApk_isIgnored() {
        val notAZip = temp.newFile("broken.apk").apply { writeText("not a zip") }
        val base = apk("base.apk", mapOf("lib/arm64-v8a/$name" to arm64Bytes))
        val library =
            NativeLibraryLocator.locate(name, null, listOf(notAZip.path, base.path), listOf("arm64-v8a"))
        assertEquals("${base.path}!/lib/arm64-v8a/$name", library?.path)
    }

    @Test
    fun sha256HexStream_matchesFileDigest() {
        val file = temp.newFile("lib.so").apply { writeBytes(arm64Bytes) }
        assertEquals(DigestUtil.sha256HexFile(file), file.inputStream().use(DigestUtil::sha256HexStream))
    }
}
