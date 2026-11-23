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
package io.mobshield.core

import io.mobshield.core.internal.MobShieldEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class UnknownSignalWarningTest {
    @Test
    fun unknownSignalNames_keepsOnlyNamesWithoutThreatType() {
        val names = listOf("android.root.su", "custom.root.check", "com.example.hook.x", "custom.root.check")
        assertEquals(listOf("custom.root.check"), MobShieldEngine.unknownSignalNames(names))
    }

    @Test
    fun unknownSignal_isWarnedOnceAcrossScans() =
        runTest {
            val warnings = mutableListOf<String>()
            val engine =
                makeEngine(
                    scope = this,
                    config = MobShieldConfig(periodicIntervalSec = 1),
                    signals = listOf(Signal(name = "custom.root.check", weight = 90, confidence = 100)),
                    warnings = warnings,
                )

            engine.start()
            advanceTimeBy(2_500)
            engine.stop()

            assertEquals(1, warnings.size)
            assertTrue(warnings.single().contains("\"custom.root.check\""))
        }

    @Test
    fun knownSignal_isNotWarned() =
        runTest {
            val warnings = mutableListOf<String>()
            val engine =
                makeEngine(
                    scope = this,
                    config = MobShieldConfig(),
                    signals = listOf(Signal(name = "android.root.custom", weight = 90, confidence = 100)),
                    warnings = warnings,
                )

            engine.start()
            advanceUntilIdle()

            assertTrue(warnings.isEmpty())
        }

    @Test
    fun unknownConfigKeys_areWarnedAtStart() =
        runTest {
            val warnings = mutableListOf<String>()
            val config =
                MobShieldConfig(
                    detectionTuning = mapOf("andriod.adb.enabled" to SignalTuning(weight = 5, confidence = 5)),
                    signalGroups = mapOf("custom.root.check" to "custom"),
                )
            val engine = makeEngine(scope = this, config = config, signals = emptyList(), warnings = warnings)

            engine.start()
            advanceUntilIdle()

            assertEquals(2, warnings.size)
            assertTrue(warnings[0].startsWith("detectionTuning"))
            assertTrue(warnings[0].contains("\"andriod.adb.enabled\""))
            assertTrue(warnings[1].startsWith("signalGroups"))
        }

    private fun makeEngine(
        scope: CoroutineScope,
        config: MobShieldConfig,
        signals: List<Signal>,
        warnings: MutableList<String>,
    ): MobShieldEngine {
        val module =
            object : DetectionModule {
                override val name: String = "custom"
                override val criticality: Int = 10

                override suspend fun scan(): List<Signal> = signals
            }
        return MobShieldEngine(
            config = config,
            listener =
                object : MobShieldListener {
                    override fun onThreat(event: ThreatEvent) = Unit

                    override fun onAllChecksFinished(events: List<ThreatEvent>) = Unit
                },
            resolveModules = { listOf(module) },
            scope = scope,
            signalSetVersion = MobShield.SIGNAL_SET_VERSION,
            selfCheck = { 1 },
            warn = { warnings.add(it) },
        )
    }
}
