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
package io.mobshield.detect.hooks

import io.mobshield.core.MobShieldConfig
import io.mobshield.core.Severity
import io.mobshield.core.SignalAggregator
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Locks the documented single-signal outcomes in `docs/scoring.md`: what each default signal
 * scores, and which severity it reaches, when it is the only signal of its threat type.
 */
class SingleSignalSeverityTest {
    private data class Expected(
        val name: String,
        val score: Int?,
        val severity: Severity?,
    )

    private val table =
        listOf(
            Expected(HookSignalDefaults.FRIDA_MAPS, score = 63, severity = Severity.HIGH),
            Expected(HookSignalDefaults.PROLOGUE, score = 72, severity = Severity.CRITICAL),
            Expected(HookSignalDefaults.FRIDA_PORT, score = 80, severity = Severity.CRITICAL),
            Expected(HookSignalDefaults.THREAD_NAME, score = 56, severity = Severity.HIGH),
            Expected(HookSignalDefaults.ART_DEX, score = 63, severity = Severity.HIGH),
            Expected(HookSignalDefaults.SUSPICIOUS_LIBRARY, score = 35, severity = Severity.HIGH),
            Expected(HookSignalDefaults.XPOSED_CLASS, score = 56, severity = Severity.HIGH),
            Expected(HookSignalDefaults.STACK_LEAK, score = 48, severity = Severity.HIGH),
        )

    @Test
    fun eachDefaultSignal_aloneMatchesDocumentedSeverity() {
        val aggregator = SignalAggregator(MobShieldConfig())
        for (row in table) {
            val signal = HookSignalDefaults.buildSignal(row.name, emptyMap(), emptyMap())
            val event = aggregator.aggregate(listOf(signal)).singleOrNull()
            assertEquals(row.name, row.score, event?.score)
            assertEquals(row.name, row.severity, event?.severity)
        }
    }
}
