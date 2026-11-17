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
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Termination needs corroboration: an event ends the process only if one of its signals reaches HIGH
 * on its own, and only if its type is in [MobShieldConfig.terminateOn]. See `docs/termination.md`.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TerminationTest {
    // Default weights of three weak root hints a custom ROM can trip: 38 + 8 + 6 = 53, which is HIGH.
    private val packages = Signal(name = "android.root.dangerous_packages", weight = 55, confidence = 70)
    private val pathProbe = Signal(name = "android.root.path_probe", weight = 25, confidence = 35)
    private val props = Signal(name = "android.root.props", weight = 20, confidence = 30)

    // Strong root signals: each is HIGH on its own (63 and 56); together they are CRITICAL.
    private val mountNamespace = Signal(name = "android.root.mount_namespace", weight = 75, confidence = 85)
    private val magiskSocket = Signal(name = "android.root.magisk_uds", weight = 70, confidence = 80)

    // CRITICAL on its own (80).
    private val fridaPort = Signal(name = "android.hook.frida_port", weight = 85, confidence = 95)

    private val bypass = MobShieldConfig(detectOnly = false, terminationPolicy = TerminationPolicy.EXIT_ON_BYPASS)
    private val critical = MobShieldConfig(detectOnly = false, terminationPolicy = TerminationPolicy.EXIT_ON_CRITICAL)

    @Test
    fun weakRootHints_reachHigh_butDoNotTerminate() =
        runTest {
            val run = scan(bypass, packages, pathProbe, props)

            assertEquals(0, run.terminated)
            val event = run.listener.threats.single()
            assertEquals(ThreatType.PRIVILEGED_ACCESS, event.type)
            assertEquals(53, event.score)
            assertEquals(Severity.HIGH, event.severity)
        }

    @Test
    fun weakHints_reachCritical_butDoNotTerminate() =
        runTest {
            val weak = (1..4).map { Signal(name = "android.root.weak_$it", weight = 20, confidence = 100) }
            val run = scan(critical, *weak.toTypedArray())

            assertEquals(0, run.terminated)
            assertEquals(Severity.CRITICAL, run.listener.threats.single().severity)
        }

    @Test
    fun weakHints_plusOneStrongSignal_terminate() =
        runTest {
            val run = scan(bypass, packages, pathProbe, props, mountNamespace)

            assertEquals(1, run.terminated)
        }

    @Test
    fun twoStrongRootSignals_terminateOnCritical() =
        runTest {
            val run = scan(critical, mountNamespace, magiskSocket)

            assertEquals(1, run.terminated)
            assertEquals(Severity.CRITICAL, run.listener.threats.single().severity)
        }

    @Test
    fun strongSignalOfAnotherType_doesNotCorroborate() =
        runTest {
            val config = bypass.copy(terminateOn = setOf(ThreatType.PRIVILEGED_ACCESS))
            val run = scan(config, packages, pathProbe, props, fridaPort)

            // The hook is strong but not allowed to terminate; the root event has no strong signal.
            assertEquals(0, run.terminated)
            assertEquals(2, run.listener.threats.size)
        }

    @Test
    fun typeLeftOutOfTerminateOn_isReportedButNeverTerminates() =
        runTest {
            val config = critical.copy(terminateOn = ThreatType.entries.toSet() - ThreatType.PRIVILEGED_ACCESS)
            val run = scan(config, mountNamespace, magiskSocket)

            assertEquals(0, run.terminated)
            assertEquals(Severity.CRITICAL, run.listener.threats.single().severity)
        }

    @Test
    fun hookTerminatesWhenRootIsExcluded() =
        runTest {
            val config = critical.copy(terminateOn = ThreatType.entries.toSet() - ThreatType.PRIVILEGED_ACCESS)
            val run = scan(config, mountNamespace, magiskSocket, fridaPort)

            assertEquals(1, run.terminated)
        }

    @Test
    fun nativeSelfCheckFailure_terminatesOnCritical() =
        runTest {
            val run = scan(critical, selfCheck = { 0 })

            assertEquals(1, run.terminated)
            assertEquals(ThreatType.APP_INTEGRITY, run.listener.threats.single().type)
        }

    @Test
    fun eventsAreDeliveredBeforeTermination() =
        runTest {
            val run = scan(critical, mountNamespace, magiskSocket)

            assertEquals(1, run.terminated)
            assertEquals(1, run.listener.finished.size)
        }

    @Test
    fun terminateOn_defaultsToEveryType() {
        assertEquals(ThreatType.entries.toSet(), MobShieldConfig().terminateOn)
        assertEquals(ThreatType.entries.toSet(), MobShieldConfig.Builder().build().terminateOn)
    }

    @Test
    fun builder_setsTerminateOn() {
        val built =
            MobShieldConfig
                .Builder()
                .terminateOn(setOf(ThreatType.HOOK_FRAMEWORK))
                .build()

        assertEquals(setOf(ThreatType.HOOK_FRAMEWORK), built.terminateOn)
    }

    @Test
    fun typesWithStrongSignal_usesEachSignalAlone() {
        val aggregator = SignalAggregator(MobShieldConfig())

        assertTrue(aggregator.typesWithStrongSignal(listOf(packages, pathProbe, props)).isEmpty())
        assertEquals(
            setOf(ThreatType.PRIVILEGED_ACCESS, ThreatType.HOOK_FRAMEWORK),
            aggregator.typesWithStrongSignal(listOf(packages, mountNamespace, fridaPort)),
        )
    }

    private class Run(
        val listener: RecordingListener,
        val terminated: Int,
    )

    private fun TestScope.scan(
        config: MobShieldConfig,
        vararg signals: Signal,
        selfCheck: () -> Int = { 1 },
    ): Run {
        val listener = RecordingListener()
        var terminated = 0
        val module =
            object : DetectionModule {
                override val name: String = "fixed-signals"
                override val criticality: Int = 10

                override suspend fun scan(): List<Signal> = signals.toList()
            }
        val engine =
            MobShieldEngine(
                config = config,
                listener = listener,
                resolveModules = { listOf(module) },
                scope = this,
                signalSetVersion = MobShield.SIGNAL_SET_VERSION,
                terminate = { terminated++ },
                selfCheck = selfCheck,
            )
        engine.start()
        advanceUntilIdle()
        engine.stop()
        return Run(listener, terminated)
    }

    private class RecordingListener : MobShieldListener {
        val threats = mutableListOf<ThreatEvent>()
        val finished = mutableListOf<List<ThreatEvent>>()

        override fun onThreat(event: ThreatEvent) {
            threats.add(event)
        }

        override fun onAllChecksFinished(events: List<ThreatEvent>) {
            finished.add(events)
        }
    }
}
