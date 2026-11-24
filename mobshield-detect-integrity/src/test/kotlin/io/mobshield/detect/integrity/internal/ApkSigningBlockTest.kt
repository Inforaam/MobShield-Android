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

import io.mobshield.detect.integrity.internal.ApkSigningBlock.V2_BLOCK_ID
import io.mobshield.detect.integrity.internal.ApkSigningBlock.V31_BLOCK_ID
import io.mobshield.detect.integrity.internal.ApkSigningBlock.V3_BLOCK_ID
import io.mobshield.detect.integrity.internal.TestApkBuilder.signers
import io.mobshield.detect.integrity.internal.TestApkBuilder.v2Signer
import io.mobshield.detect.integrity.internal.TestApkBuilder.v3Signer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ApkSigningBlockTest {
    @get:Rule
    val temp = TemporaryFolder()

    private val ours = "ours".toByteArray()
    private val theirs = "theirs".toByteArray()
    private val original = "original".toByteArray()

    private fun trusted(
        blocks: Map<Int, ByteArray>,
        sdkInt: Int,
    ): List<String>? {
        val parsed = ApkSigningBlock.read(TestApkBuilder.apk(temp.newFile(), blocks)) ?: return null
        return ApkSigningBlock.trustedCertificates(parsed, sdkInt)?.map { String(it) }
    }

    @Test
    fun v2Only_returnsTheV2Signer() {
        assertEquals(listOf("ours"), trusted(mapOf(V2_BLOCK_ID to signers(v2Signer(ours))), sdkInt = 30))
    }

    @Test
    fun v3Present_ignoresTheV2BlockOnApi28AndLater() {
        val blocks = mapOf(V2_BLOCK_ID to signers(v2Signer(ours)), V3_BLOCK_ID to signers(v3Signer(theirs)))
        assertEquals(listOf("theirs"), trusted(blocks, sdkInt = 30))
    }

    @Test
    fun v3Present_usesV2BeforeApi28() {
        val blocks = mapOf(V2_BLOCK_ID to signers(v2Signer(ours)), V3_BLOCK_ID to signers(v3Signer(theirs)))
        assertEquals(listOf("ours"), trusted(blocks, sdkInt = 27))
    }

    @Test
    fun v31_isUsedFromApi33() {
        val blocks =
            mapOf(
                V3_BLOCK_ID to signers(v3Signer(original)),
                V31_BLOCK_ID to signers(v3Signer(ours, minSdk = 33)),
            )
        assertEquals(listOf("ours"), trusted(blocks, sdkInt = 34))
        assertEquals(listOf("original"), trusted(blocks, sdkInt = 32))
    }

    @Test
    fun v3Signer_outsideItsSdkRange_isNotUsed() {
        val blocks =
            mapOf(
                V3_BLOCK_ID to signers(v3Signer(theirs, minSdk = 24, maxSdk = 29), v3Signer(ours, minSdk = 30)),
            )
        assertEquals(listOf("ours"), trusted(blocks, sdkInt = 31))
    }

    @Test
    fun rotationLineage_isIncluded() {
        val blocks = mapOf(V3_BLOCK_ID to signers(v3Signer(ours, lineage = listOf(original, ours))))
        assertEquals(listOf("ours", "original", "ours"), trusted(blocks, sdkInt = 30))
    }

    @Test
    fun noSigningBlock_returnsNull() {
        assertNull(ApkSigningBlock.read(TestApkBuilder.apk(temp.newFile(), emptyMap())))
    }

    @Test
    fun notAZip_returnsNull() {
        assertNull(ApkSigningBlock.read(temp.newFile().apply { writeText("not an apk") }))
    }

    @Test
    fun truncatedSignerData_returnsNull() {
        val broken = TestApkBuilder.le32(100) + byteArrayOf(1, 2)
        assertNull(ApkSigningBlock.read(TestApkBuilder.apk(temp.newFile(), mapOf(V2_BLOCK_ID to broken))))
    }
}
