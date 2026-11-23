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
package io.mobshield.detect.debugger

import io.mobshield.core.SignalTuning
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DebugSignalTuningTest {
    private val adbHit = AdbEnabledCheck.ScanHit(adbEnabled = true, usbDebugging = false)
    private val releaseHit = AppDebuggable.ScanHit(isReleaseBuild = true)

    @Test
    fun adbSignal_usesDefaultsWithoutTuning() {
        val signal = DebugDetectionModule.adbSignals(adbHit, emptyMap()).single()
        assertEquals(30, signal.weight)
        assertEquals(40, signal.confidence)
    }

    @Test
    fun adbSignal_usesCallerTuning() {
        val tuning = mapOf(DebugSignalDefaults.ADB_ENABLED to SignalTuning(weight = 5, confidence = 10))
        val signal = DebugDetectionModule.adbSignals(adbHit, tuning).single()
        assertEquals(5, signal.weight)
        assertEquals(10, signal.confidence)
    }

    @Test
    fun adbSignal_noHit_isEmpty() {
        assertTrue(DebugDetectionModule.adbSignals(null, emptyMap()).isEmpty())
    }

    @Test
    fun appDebuggableSignal_usesDefaultsWithoutTuning() {
        val signal = DebugDetectionModule.appDebuggableSignals(releaseHit, emptyMap()).single()
        assertEquals(70, signal.weight)
        assertEquals(60, signal.confidence)
    }

    @Test
    fun appDebuggableSignal_usesCallerTuning() {
        val tuning = mapOf(DebugSignalDefaults.APP_DEBUGGABLE to SignalTuning(weight = 95, confidence = 90))
        val signal = DebugDetectionModule.appDebuggableSignals(releaseHit, tuning).single()
        assertEquals(95, signal.weight)
        assertEquals(90, signal.confidence)
    }

    @Test
    fun appDebuggableSignal_debugBuild_isEmpty() {
        val debugHit = AppDebuggable.ScanHit(isReleaseBuild = false)
        assertTrue(DebugDetectionModule.appDebuggableSignals(debugHit, emptyMap()).isEmpty())
    }
}
