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

import io.mobshield.core.SignalTuning
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PackageIdCheckTest {
    @Test
    fun scan_notConfigured_returnsNull() {
        assertNull(PackageIdCheck(expectedPackageId = null, actualPackageName = "com.example.app").scan())
    }

    @Test
    fun scan_matching_returnsNull() {
        assertNull(PackageIdCheck(expectedPackageId = "com.example.app", actualPackageName = "com.example.app").scan())
    }

    @Test
    fun scan_differentPackage_returnsHit() {
        val hit = PackageIdCheck(expectedPackageId = "com.example.app", actualPackageName = "com.other.app").scan()
        assertEquals("com.example.app", hit?.expected)
        assertEquals("com.other.app", hit?.actual)
    }

    @Test
    fun packageIdSignals_usesDefaultsAndTuning() {
        val hit = PackageIdCheck.ScanHit(expected = "com.example.app", actual = "com.other.app")
        val default = IntegrityDetectionModule.packageIdSignals(hit, emptyMap()).single()
        assertEquals(IntegritySignalDefaults.PACKAGE_ID, default.name)
        assertEquals(85, default.weight)
        assertEquals("com.other.app", default.evidence["actual"])

        val tuned =
            IntegrityDetectionModule
                .packageIdSignals(hit, mapOf(IntegritySignalDefaults.PACKAGE_ID to SignalTuning(10, 20)))
                .single()
        assertEquals(10, tuned.weight)
        assertTrue(IntegrityDetectionModule.packageIdSignals(null, emptyMap()).isEmpty())
    }
}
