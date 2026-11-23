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

import io.mobshield.detect.integrity.NativeLibChecksumCheck.NativeLibrary
import java.io.File
import java.io.FileNotFoundException
import java.io.FilterInputStream
import java.io.InputStream
import java.util.zip.ZipFile

/**
 * Finds a native library where the platform loads it from: extracted under `nativeLibraryDir`, or
 * in place from `lib/<abi>/` of the base or a split APK. The ABI is the first of `abis` (device
 * preference order) that an APK ships the library for.
 */
internal object NativeLibraryLocator {
    fun locate(
        libraryName: String,
        nativeLibraryDir: String?,
        apkPaths: List<String>,
        abis: List<String>,
    ): NativeLibrary? {
        val inApk = findInApks(libraryName, apkPaths, abis)
        val extracted = nativeLibraryDir?.takeIf { it.isNotBlank() }?.let { File(it, libraryName) }
        if (extracted != null && extracted.isFile) {
            return NativeLibrary(abi = inApk?.first, path = extracted.absolutePath) { extracted.inputStream() }
        }
        val (abi, apk) = inApk ?: return null
        val entryName = entryName(abi, libraryName)
        return NativeLibrary(abi = abi, path = "$apk!/$entryName") { openEntry(apk, entryName) }
    }

    private fun findInApks(
        libraryName: String,
        apkPaths: List<String>,
        abis: List<String>,
    ): Pair<String, String>? {
        val abisByApk = apkPaths.associateWith { apk -> abisIn(apk, libraryName, abis) }
        for (abi in abis) {
            val apk = abisByApk.entries.firstOrNull { abi in it.value }?.key
            if (apk != null) {
                return abi to apk
            }
        }
        return null
    }

    private fun abisIn(
        apk: String,
        libraryName: String,
        abis: List<String>,
    ): List<String> =
        runCatching {
            ZipFile(apk).use { zip -> abis.filter { zip.getEntry(entryName(it, libraryName)) != null } }
        }.getOrDefault(emptyList())

    private fun openEntry(
        apk: String,
        entryName: String,
    ): InputStream {
        val zip = ZipFile(apk)
        val entry =
            zip.getEntry(entryName) ?: run {
                zip.close()
                throw FileNotFoundException(entryName)
            }
        return object : FilterInputStream(zip.getInputStream(entry)) {
            override fun close() {
                try {
                    super.close()
                } finally {
                    zip.close()
                }
            }
        }
    }

    private fun entryName(
        abi: String,
        libraryName: String,
    ) = "lib/$abi/$libraryName"
}
