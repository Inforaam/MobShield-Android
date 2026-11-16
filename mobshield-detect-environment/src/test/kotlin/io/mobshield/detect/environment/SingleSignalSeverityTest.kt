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
package io.mobshield.detect.environment

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
            Expected(EmuSignalDefaults.QEMU_PROPS, score = 14, severity = Severity.MEDIUM),
            Expected(EmuSignalDefaults.QEMU_DEVICE, score = 21, severity = Severity.MEDIUM),
            Expected(EmuSignalDefaults.CPU_GOLDFISH, score = 16, severity = Severity.MEDIUM),
            Expected(EmuSignalDefaults.BUILD_FINGERPRINT, score = 12, severity = Severity.MEDIUM),
            Expected(EmuSignalDefaults.SENSOR_COUNT, score = 9, severity = Severity.LOW),
            Expected(EmuSignalDefaults.AUTOMATION, score = 21, severity = Severity.MEDIUM),
        )

    @Test
    fun eachDefaultSignal_aloneMatchesDocumentedSeverity() {
        val aggregator = SignalAggregator(MobShieldConfig())
        for (row in table) {
            val signal = EmuSignalDefaults.buildSignal(row.name, emptyMap(), emptyMap())
            val event = aggregator.aggregate(listOf(signal)).singleOrNull()
            assertEquals(row.name, row.score, event?.score)
            assertEquals(row.name, row.severity, event?.severity)
        }
    }
}
