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
import org.junit.Test

class InstallerSignalTuningTest {
    private val hit =
        InstallerOriginCheck.ScanHit(
            installer = "com.unknown.store",
            allowed = listOf("com.android.vending"),
        )

    @Test
    fun installerSignal_usesDefaultsWithoutTuning() {
        val signal = IntegrityDetectionModule.installerSignals(hit, emptyMap()).single()
        assertEquals(25, signal.weight)
        assertEquals(45, signal.confidence)
    }

    @Test
    fun installerSignal_usesCallerTuning() {
        val tuning = mapOf(IntegritySignalDefaults.INSTALLER to SignalTuning(weight = 60, confidence = 80))
        val signal = IntegrityDetectionModule.installerSignals(hit, tuning).single()
        assertEquals(60, signal.weight)
        assertEquals(80, signal.confidence)
    }
}
