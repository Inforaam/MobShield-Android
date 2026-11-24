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

import java.io.File
import java.io.RandomAccessFile
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Reads signer certificates from the APK Signature Scheme v2/v3/v3.1 block of an installed APK,
 * without going through `PackageManager`.
 *
 * Only the scheme the platform verifies at the given API level is used, and within it only signers
 * whose SDK range covers that level, together with the v3 proof-of-rotation lineage.
 */
internal object ApkSigningBlock {
    const val V2_BLOCK_ID = 0x7109871a
    const val V3_BLOCK_ID = 0xf05368c0.toInt()
    const val V31_BLOCK_ID = 0x1b93ad61
    const val ROTATION_ATTR_ID = 0x3ba06f8c

    private const val EOCD_MAGIC = 0x06054b50
    private const val EOCD_SIZE = 22
    private const val EOCD_CD_OFFSET = 16
    private const val MAX_COMMENT = 0xFFFF
    private const val FOOTER_SIZE = 24
    private const val MAX_BLOCK_SIZE = 64L * 1024 * 1024
    private const val API_P = 28
    private const val API_T = 33
    private val BLOCK_MAGIC = "APK Sig Block 42".toByteArray(Charsets.US_ASCII)

    class Signer(
        val minSdk: Int,
        val maxSdk: Int,
        val certificates: List<ByteArray>,
        val lineage: List<ByteArray>,
    )

    /** Signers per block ID, or null when the APK has no signing block. */
    fun read(apk: File): Map<Int, List<Signer>>? {
        val pairs = RandomAccessFile(apk, "r").use(::readPairs) ?: return null
        return try {
            buildMap {
                pairs[V2_BLOCK_ID]?.let { put(V2_BLOCK_ID, parseSigners(it, v3 = false)) }
                pairs[V3_BLOCK_ID]?.let { put(V3_BLOCK_ID, parseSigners(it, v3 = true)) }
                pairs[V31_BLOCK_ID]?.let { put(V31_BLOCK_ID, parseSigners(it, v3 = true)) }
            }
        } catch (_: BufferUnderflowException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    /**
     * Certificates the platform trusts at [sdkInt]: the first certificate of each applicable signer of
     * the highest scheme that has one, plus that signer's rotation lineage. Null when no scheme applies.
     */
    fun trustedCertificates(
        blocks: Map<Int, List<Signer>>,
        sdkInt: Int,
    ): List<ByteArray>? {
        val order =
            buildList {
                if (sdkInt >= API_T) add(V31_BLOCK_ID)
                if (sdkInt >= API_P) add(V3_BLOCK_ID)
                add(V2_BLOCK_ID)
            }
        for (id in order) {
            val signers = blocks[id] ?: continue
            val applicable = if (id == V2_BLOCK_ID) signers else signers.filter { sdkInt in it.minSdk..it.maxSdk }
            if (applicable.isEmpty()) {
                continue
            }
            return applicable.flatMap { listOfNotNull(it.certificates.firstOrNull()) + it.lineage }
        }
        return null
    }

    private fun readPairs(file: RandomAccessFile): Map<Int, ByteBuffer>? {
        val cdOffset = centralDirectoryOffset(file) ?: return null
        if (cdOffset < FOOTER_SIZE) {
            return null
        }
        val footer = readAt(file, cdOffset - FOOTER_SIZE, FOOTER_SIZE)
        if (!footer.copyOfRange(8, FOOTER_SIZE).contentEquals(BLOCK_MAGIC)) {
            return null
        }
        val blockSize = ByteBuffer.wrap(footer, 0, 8).order(ByteOrder.LITTLE_ENDIAN).long
        val blockStart = cdOffset - blockSize - 8
        if (blockSize < FOOTER_SIZE || blockSize > MAX_BLOCK_SIZE || blockStart < 0) {
            return null
        }
        val block = ByteBuffer.wrap(readAt(file, blockStart, (blockSize + 8).toInt())).order(ByteOrder.LITTLE_ENDIAN)
        if (block.long != blockSize) {
            return null
        }
        val pairsEnd = block.capacity() - FOOTER_SIZE
        val pairs = HashMap<Int, ByteBuffer>()
        while (block.position() + 12 <= pairsEnd) {
            val length = block.long
            if (length < 4 || length > pairsEnd - block.position()) {
                return null
            }
            val id = block.int
            pairs[id] = slice(block, (length - 4).toInt())
        }
        return pairs
    }

    private fun centralDirectoryOffset(file: RandomAccessFile): Long? {
        val length = file.length()
        if (length < EOCD_SIZE) {
            return null
        }
        val tailSize = minOf(length, (EOCD_SIZE + MAX_COMMENT).toLong()).toInt()
        val tail = ByteBuffer.wrap(readAt(file, length - tailSize, tailSize)).order(ByteOrder.LITTLE_ENDIAN)
        for (pos in tailSize - EOCD_SIZE downTo 0) {
            val commentLength = tail.getShort(pos + EOCD_SIZE - 2).toInt() and 0xFFFF
            if (tail.getInt(pos) == EOCD_MAGIC && pos + EOCD_SIZE + commentLength == tailSize) {
                return tail.getInt(pos + EOCD_CD_OFFSET).toLong() and 0xFFFFFFFFL
            }
        }
        return null
    }

    private fun parseSigners(
        value: ByteBuffer,
        v3: Boolean,
    ): List<Signer> {
        val signers = lengthPrefixed(value)
        val result = ArrayList<Signer>()
        while (signers.hasRemaining()) {
            val signer = lengthPrefixed(signers)
            val signedData = lengthPrefixed(signer)
            lengthPrefixed(signedData)
            val certificates = readSequence(lengthPrefixed(signedData))
            if (!v3) {
                result.add(Signer(0, Int.MAX_VALUE, certificates, emptyList()))
                continue
            }
            val minSdk = signedData.int
            val maxSdk = signedData.int
            val lineage = rotationLineage(lengthPrefixed(signedData))
            result.add(Signer(minSdk, maxSdk, certificates, lineage))
        }
        return result
    }

    private fun rotationLineage(attributes: ByteBuffer): List<ByteArray> {
        while (attributes.hasRemaining()) {
            val attribute = lengthPrefixed(attributes)
            if (attribute.int != ROTATION_ATTR_ID) {
                continue
            }
            attribute.int
            val certificates = ArrayList<ByteArray>()
            while (attribute.hasRemaining()) {
                val node = lengthPrefixed(attribute)
                val signedData = lengthPrefixed(node)
                certificates.add(bytes(lengthPrefixed(signedData)))
            }
            return certificates
        }
        return emptyList()
    }

    private fun readSequence(buffer: ByteBuffer): List<ByteArray> {
        val items = ArrayList<ByteArray>()
        while (buffer.hasRemaining()) {
            items.add(bytes(lengthPrefixed(buffer)))
        }
        return items
    }

    private fun lengthPrefixed(buffer: ByteBuffer): ByteBuffer {
        val length = buffer.int
        require(length >= 0 && length <= buffer.remaining()) { "bad length" }
        return slice(buffer, length)
    }

    private fun slice(
        buffer: ByteBuffer,
        length: Int,
    ): ByteBuffer {
        val slice = buffer.slice().order(ByteOrder.LITTLE_ENDIAN)
        slice.limit(length)
        buffer.position(buffer.position() + length)
        return slice
    }

    private fun bytes(buffer: ByteBuffer): ByteArray = ByteArray(buffer.remaining()).also { buffer.get(it) }

    private fun readAt(
        file: RandomAccessFile,
        offset: Long,
        size: Int,
    ): ByteArray {
        val bytes = ByteArray(size)
        file.seek(offset)
        file.readFully(bytes)
        return bytes
    }
}
