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

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.mobshield.detect.hooks.internal.HooksNativeBridge
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.ServerSocket

/**
 * Regression test for the loopback probe: a non-blocking connect() to a listening port returns
 * EINPROGRESS, so the probe must wait for completion instead of expecting an immediate success.
 */
@RunWith(AndroidJUnit4::class)
class FridaPortProbeInstrumentedTest {
    private val loopback: InetAddress = InetAddress.getByName("127.0.0.1")

    @Test
    fun probe_detectsListenerOnFridaPort() {
        val server = openOrSkip(FRIDA_PORT)
        server.use {
            val result = HooksNativeBridge.fridaPortProbe()
            assertEquals(HooksNativeBridge.RESULT_DETECTED, result.code)
            assertEquals("port:$FRIDA_PORT", result.evidence)
        }
    }

    @Test
    fun probe_detectsListenerOnSecondFridaPort() {
        val server = openOrSkip(FRIDA_PORT_ALT)
        server.use {
            val result = HooksNativeBridge.fridaPortProbe()
            assertEquals(HooksNativeBridge.RESULT_DETECTED, result.code)
            assertEquals("port:$FRIDA_PORT_ALT", result.evidence)
        }
    }

    @Test
    fun probe_isCleanWhenNothingListens() {
        val first = runCatching { ServerSocket(FRIDA_PORT, 1, loopback) }.getOrNull()
        val second = runCatching { ServerSocket(FRIDA_PORT_ALT, 1, loopback) }.getOrNull()
        try {
            // Only meaningful if both ports were free, which also proves nothing else listens there.
            assumeTrue(first != null && second != null)
            first?.close()
            second?.close()
            assertEquals(HooksNativeBridge.RESULT_OK, HooksNativeBridge.fridaPortProbe().code)
        } finally {
            first?.close()
            second?.close()
        }
    }

    private fun openOrSkip(port: Int): ServerSocket {
        val server = runCatching { ServerSocket(port, 1, loopback) }.getOrNull()
        assumeTrue("port $port is already in use", server != null)
        return server!!
    }

    private companion object {
        const val FRIDA_PORT = 27042
        const val FRIDA_PORT_ALT = 27043
    }
}
