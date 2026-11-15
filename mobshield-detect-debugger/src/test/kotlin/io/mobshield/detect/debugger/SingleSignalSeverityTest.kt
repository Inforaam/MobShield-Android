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
            Expected(DebugSignalDefaults.TRACERPID, score = 76, severity = Severity.CRITICAL),
            Expected(DebugSignalDefaults.PTRACE, score = 68, severity = Severity.CRITICAL),
            Expected(DebugSignalDefaults.TIMING, score = 45, severity = Severity.HIGH),
            Expected(DebugSignalDefaults.APP_DEBUGGABLE, score = 42, severity = Severity.HIGH),
            Expected(DebugSignalDefaults.ADB_ENABLED, score = 12, severity = Severity.INFO),
            Expected(DebugSignalDefaults.WAITING_DEBUGGER, score = 85, severity = Severity.CRITICAL),
        )

    @Test
    fun eachDefaultSignal_aloneMatchesDocumentedSeverity() {
        val aggregator = SignalAggregator(MobShieldConfig())
        for (row in table) {
            val signal = DebugSignalDefaults.buildSignal(row.name, emptyMap(), emptyMap())
            val event = aggregator.aggregate(listOf(signal)).singleOrNull()
            assertEquals(row.name, row.score, event?.score)
            assertEquals(row.name, row.severity, event?.severity)
        }
    }
}
