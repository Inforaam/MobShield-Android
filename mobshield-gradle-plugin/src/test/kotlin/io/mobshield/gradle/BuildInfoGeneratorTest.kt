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

package io.mobshield.gradle

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BuildInfoGeneratorTest {
    @Test
    fun generate_producesADifferentBuildIdPerSeed() {
        val first = BuildInfoGenerator.generate(request(seed = "a".repeat(64)))
        val second = BuildInfoGenerator.generate(request(seed = "b".repeat(64)))
        assertNotEquals(first.buildId, second.buildId)
        assertNotEquals(first.headerContent, second.headerContent)
    }

    @Test
    fun generate_isReproducibleForAFixedSeed() {
        val first = BuildInfoGenerator.generate(request(seed = "a".repeat(64)))
        val second = BuildInfoGenerator.generate(request(seed = "a".repeat(64)))
        assertEquals(first.headerContent, second.headerContent)
    }

    @Test
    fun generate_writesAPublicBuildId() {
        val result = BuildInfoGenerator.generate(request())
        assertTrue(Regex("android-[0-9a-f]{16}").matches(result.buildId))
        assertTrue(result.headerContent.contains("#define MOBSHIELD_BUILD_ID \"${result.buildId}\""))
    }

    @Test
    fun generate_writesNoKeyMaterial() {
        // Everything in the header ends up readable in the app's binary, so it must not hold anything
        // used as a key. These were removed because they were keyed by a value stored beside them.
        val header = BuildInfoGenerator.generate(request()).headerContent
        listOf("ENTROPY", "HMAC", "CIPHERTEXT", "NONCE", "SALT", "MOBSHIELD_R_").forEach {
            assertFalse("Header must not contain $it", header.contains(it))
        }
    }

    @Test
    fun generate_buildIdDoesNotRevealTheSeed() {
        val seed = "0123456789abcdef".repeat(4)
        val result = BuildInfoGenerator.generate(request(seed = seed))
        assertFalse(result.headerContent.contains(seed.take(16)))
    }

    @Test
    fun shouldSkipGeneration_whenFingerprintMatches() {
        val dir = createTempDir()
        val header = dir.resolve("mobshield_buildinfo.h")
        val inputs = dir.resolve("inputs.fingerprint")
        val result = BuildInfoGenerator.generate(request())
        header.writeText(result.headerContent)
        inputs.writeText(result.inputsFingerprint)
        assertTrue(BuildInfoGenerator.shouldSkipGeneration(inputs, header, result.inputsFingerprint))
    }

    private fun request(seed: String? = null): BuildInfoRequest {
        return BuildInfoRequest(
            expectedSigningCertSha256 = "ab".repeat(32),
            expectedPackageName = "com.example.app",
            expectedInstallers = listOf("com.android.vending"),
            aggressive = false,
            randomSeedHex = seed,
            nativeLibraries = listOf("libmobshieldcore.so", "libmobshieldroot.so"),
        )
    }
}
