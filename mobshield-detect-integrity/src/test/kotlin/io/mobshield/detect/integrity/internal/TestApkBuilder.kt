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

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Builds APK files with a synthetic APK Signing Block for parser tests. Signatures are not real. */
internal object TestApkBuilder {
    fun le32(value: Int): ByteArray =
        ByteBuffer
            .allocate(4)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(value)
            .array()

    private fun le64(value: Long): ByteArray =
        ByteBuffer
            .allocate(8)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putLong(value)
            .array()

    fun lp(vararg parts: ByteArray): ByteArray {
        val body = parts.fold(ByteArray(0)) { acc, part -> acc + part }
        return le32(body.size) + body
    }

    fun v2Signer(cert: ByteArray): ByteArray = lp(lp(lp(), lp(lp(cert)), lp()), lp(), lp())

    fun v3Signer(
        cert: ByteArray,
        minSdk: Int = 24,
        maxSdk: Int = Int.MAX_VALUE,
        lineage: List<ByteArray> = emptyList(),
    ): ByteArray {
        val attributes =
            if (lineage.isEmpty()) {
                lp()
            } else {
                val nodes = lineage.map { lp(lp(lp(it), le32(0)), le32(0), le32(0), lp()) }.toTypedArray()
                lp(lp(le32(ApkSigningBlock.ROTATION_ATTR_ID), le32(1), *nodes))
            }
        val signedData = lp(lp(), lp(lp(cert)), le32(minSdk), le32(maxSdk), attributes)
        return lp(signedData, le32(minSdk), le32(maxSdk), lp(), lp())
    }

    fun signers(vararg signers: ByteArray): ByteArray = lp(*signers)

    fun apk(
        file: File,
        blocks: Map<Int, ByteArray>,
    ): File {
        val zip =
            ByteArrayOutputStream()
                .also { out ->
                    ZipOutputStream(out).use { zip ->
                        zip.putNextEntry(ZipEntry("classes.dex"))
                        zip.write(byteArrayOf(1, 2, 3))
                        zip.closeEntry()
                    }
                }.toByteArray()
        if (blocks.isEmpty()) {
            return file.apply { writeBytes(zip) }
        }
        val pairs =
            blocks.entries.fold(ByteArray(0)) { acc, (id, value) ->
                acc + le64(4L + value.size) + le32(id) +
                    value
            }
        val blockSize = pairs.size + 24L
        val block = le64(blockSize) + pairs + le64(blockSize) + "APK Sig Block 42".toByteArray(Charsets.US_ASCII)

        val eocd =
            (zip.size - 22 downTo 0).first {
                ByteBuffer.wrap(zip, it, 4).order(ByteOrder.LITTLE_ENDIAN).int ==
                    0x06054b50
            }
        val cdOffset = ByteBuffer.wrap(zip).order(ByteOrder.LITTLE_ENDIAN).getInt(eocd + 16)
        val result = zip.copyOfRange(0, cdOffset) + block + zip.copyOfRange(cdOffset, zip.size)
        ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN).putInt(eocd + block.size + 16, cdOffset + block.size)
        return file.apply { writeBytes(result) }
    }
}
