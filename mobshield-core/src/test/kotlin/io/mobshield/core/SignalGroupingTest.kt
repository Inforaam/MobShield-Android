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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SignalGroupingTest {
    private val grouped = MobShieldConfig()
    private val ungrouped = MobShieldConfig(signalGroups = emptyMap())

    private fun signal(
        name: String,
        weight: Int,
        confidence: Int,
    ) = Signal(name = name, weight = weight, confidence = confidence, timestampMs = 1L)

    private fun score(
        config: MobShieldConfig,
        vararg signals: Signal,
    ): Int = SignalAggregator(config).aggregate(signals.toList()).single().score

    @Test
    fun singleSignal_scoreUnchangedByGrouping() {
        val port = signal("android.hook.frida_port", 85, 95)
        assertEquals(80, score(grouped, port))
        assertEquals(80, score(ungrouped, port))
    }

    @Test
    fun fridaMapsAndThreads_combineWithDiminishingReturns() {
        val maps = signal("common.hook.frida_maps", 75, 85)
        val threads = signal("android.hook.thread_name", 70, 80)
        assertEquals(100, score(ungrouped, maps, threads))
        assertEquals(84, score(grouped, maps, threads))
    }

    @Test
    fun sameMapsFileReadTwice_isNotCountedTwice() {
        val maps = signal("common.hook.frida_maps", 75, 85)
        val library = signal("android.hook.suspicious_library", 55, 65)
        assertEquals(99, score(ungrouped, maps, library))
        assertEquals(76, score(grouped, maps, library))
    }

    @Test
    fun differentGroups_stillAdd() {
        val maps = signal("common.hook.frida_maps", 75, 85)
        val xposed = signal("android.hook.xposed", 70, 80)
        assertEquals(100, score(grouped, maps, xposed))
    }

    @Test
    fun ungroupedSignals_addAsBefore() {
        val events =
            SignalAggregator(grouped).aggregate(
                listOf(
                    signal("android.root.path_probe", 25, 35),
                    signal("android.root.props", 20, 30),
                    signal("android.root.dangerous_packages", 55, 70),
                ),
            )
        assertEquals(53, events.single().score)
        assertEquals(Severity.HIGH, events.single().severity)
    }

    @Test
    fun rootMountPair_staysCritical() {
        val event =
            SignalAggregator(grouped)
                .aggregate(
                    listOf(
                        signal("android.root.mount_namespace", 75, 85),
                        signal("android.root.overlayfs", 65, 75),
                    ),
                ).single()
        assertEquals(81, event.score)
        assertEquals(Severity.CRITICAL, event.severity)
    }

    @Test
    fun tracerPair_combined() {
        val tracerPid = signal("android.debug.tracerpid", 85, 90)
        val ptrace = signal("android.debug.ptrace", 80, 85)
        assertEquals(92, score(grouped, tracerPid, ptrace))
    }

    @Test
    fun groupIsBetweenStrongestMemberAndSum() {
        val cases =
            listOf(
                listOf(10 to 100, 10 to 100),
                listOf(50 to 100, 50 to 100),
                listOf(75 to 85, 70 to 80, 55 to 65),
                listOf(25 to 35, 60 to 70),
                listOf(100 to 100, 30 to 30),
            )
        for (case in cases) {
            val signals =
                case.mapIndexed { index, (weight, confidence) ->
                    signal(if (index == 0) "common.hook.frida_maps" else "android.hook.thread_name", weight, confidence)
                }
            val strongest = case.maxOf { (weight, confidence) -> weight * confidence / 100 }
            val sum = minOf(100, case.sumOf { (weight, confidence) -> weight * confidence } / 100)
            val combined = SignalAggregator.scoreOf(signals, DefaultSignalGroups.map)
            assertTrue("$case: $combined < $strongest", combined >= strongest)
            assertTrue("$case: $combined > $sum", combined <= sum)
        }
    }

    @Test
    fun signalOrder_doesNotChangeScore() {
        val signals =
            listOf(
                signal("common.hook.frida_maps", 75, 85),
                signal("common.hook.prologue", 80, 90),
                signal("android.hook.frida_port", 85, 95),
                signal("android.hook.thread_name", 70, 80),
                signal("android.hook.suspicious_library", 55, 65),
            )
        val forward = SignalAggregator.scoreOf(signals, DefaultSignalGroups.map)
        val backward = SignalAggregator.scoreOf(signals.reversed(), DefaultSignalGroups.map)
        assertEquals(99, forward)
        assertEquals(forward, backward)
    }

    @Test
    fun integerArithmetic_isExactAtThresholds() {
        // 50 x 60 / 100 = 30 exactly; floating point could produce 29.999... and truncate to 29.
        val timing = listOf(signal("android.debug.timing", 50, 60))
        assertEquals(30, SignalAggregator.scoreOf(timing, emptyMap()))
        val maps = listOf(signal("common.hook.frida_maps", 40, 100))
        assertEquals(40, SignalAggregator.scoreOf(maps, DefaultSignalGroups.map))
    }

    @Test
    fun customGroups_override() {
        val config =
            MobShieldConfig(
                signalGroups = mapOf("android.root.props" to "mine", "android.root.path_probe" to "mine"),
            )
        val events =
            SignalAggregator(config).aggregate(
                listOf(
                    signal("android.root.path_probe", 50, 100),
                    signal("android.root.props", 50, 100),
                ),
            )
        assertEquals(75, events.single().score)
    }

    @Test
    fun builder_setsSignalGroups() {
        val config = MobShieldConfig.Builder().signalGroups(emptyMap()).build()
        assertTrue(config.signalGroups.isEmpty())
        assertEquals(DefaultSignalGroups.map, MobShieldConfig.Builder().build().signalGroups)
    }
}
