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

import io.mobshield.detect.integrity.IntegrityDetectionModule.CheckResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test
import java.util.concurrent.CountDownLatch

class IntegrityCheckRunnerTest {
    @Test
    fun runCheck_returnsTheBlockResult() =
        runBlocking {
            val result = CheckResult(emptyList())
            assertSame(result, IntegrityDetectionModule.runCheck("signature", 1_000) { result })
        }

    @Test
    fun runCheck_blockingPastTheTimeout_isReportedAndInterrupted() =
        runBlocking {
            val interrupted = CountDownLatch(1)
            val result =
                IntegrityDetectionModule.runCheck("apk_checksum", 50) {
                    try {
                        Thread.sleep(10_000)
                    } catch (e: InterruptedException) {
                        interrupted.countDown()
                        throw e
                    }
                    CheckResult.CLEAN
                }
            assertEquals("apk_checksum:timeout", result.unavailable)
            assertEquals(0L, interrupted.count)
        }

    @Test
    fun runCheck_exception_isReported() =
        runBlocking {
            val result = IntegrityDetectionModule.runCheck("signature", 1_000) { error("boom") }
            assertEquals("signature:error", result.unavailable)
        }

    @Test(expected = CancellationException::class)
    fun runCheck_cancellation_propagates(): Unit =
        runBlocking {
            IntegrityDetectionModule.runCheck("signature", 1_000) { throw CancellationException("scan cancelled") }
        }

    @Test
    fun unavailableSignal_combinesAllChecksIntoOneSignal() {
        val signal =
            IntegrityDetectionModule.unavailableSignal(
                listOf(
                    CheckResult.unavailable("native_lib_checksum", "missing_file"),
                    CheckResult.CLEAN,
                    CheckResult.unavailable("apk_checksum", "timeout"),
                ),
                emptyMap(),
            )
        assertEquals(IntegritySignalDefaults.CHECK_UNAVAILABLE, signal?.name)
        assertEquals("apk_checksum:timeout,native_lib_checksum:missing_file", signal?.evidence?.get("checks"))
    }

    @Test
    fun unavailableSignal_allChecksRan_returnsNull() {
        assertNull(IntegrityDetectionModule.unavailableSignal(listOf(CheckResult.CLEAN), emptyMap()))
    }
}
