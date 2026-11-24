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

import io.mobshield.core.MobShieldConfig
import io.mobshield.core.SignalAggregator
import io.mobshield.core.ThreatType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class InstallerOriginCheckTest {
    @Test
    fun scan_playStoreInstaller_returnsNull() {
        val check =
            InstallerOriginCheck(
                allowedInstallSources = MobShieldConfig.DEFAULT_ALLOWED_INSTALL_SOURCES,
                installingPackageProvider = { "com.android.vending" },
            )
        assertNull(check.scan())
    }

    @Test
    fun scan_unknownInstaller_returnsHit() {
        val check =
            InstallerOriginCheck(
                allowedInstallSources = MobShieldConfig.DEFAULT_ALLOWED_INSTALL_SOURCES,
                installingPackageProvider = { "com.unknown.store" },
            )
        assertNotNull(check.scan())
    }

    @Test
    fun installerSignal_mapsToUnofficialStore() {
        val signal =
            IntegritySignalDefaults.buildSignal(
                IntegritySignalDefaults.INSTALLER,
                mapOf("installer" to "com.unknown.store"),
                emptyMap(),
            )
        val event = SignalAggregator(MobShieldConfig()).aggregate(listOf(signal)).single()
        assertEquals(ThreatType.UNOFFICIAL_STORE, event.type)
    }

    @Test
    fun scan_allowedInstallerStartedByAnotherApp_returnsHit() {
        val check =
            InstallerOriginCheck(
                allowedInstallSources = setOf("com.android.vending"),
                installingPackageProvider = { "com.android.vending" },
                initiatingPackageProvider = { "com.android.shell" },
            )
        assertEquals("com.android.shell", check.scan()?.initiating)
    }

    @Test
    fun scan_initiatingMatchesInstallerOrIsAllowed_returnsNull() {
        for (initiating in listOf(null, "com.android.vending", "com.allowed.store")) {
            val check =
                InstallerOriginCheck(
                    allowedInstallSources = setOf("com.android.vending", "com.allowed.store"),
                    installingPackageProvider = { "com.android.vending" },
                    initiatingPackageProvider = { initiating },
                )
            assertNull(initiating, check.scan())
        }
    }

    @Test
    fun installerSignals_includeInitiatingWhenSet() {
        val hit =
            InstallerOriginCheck.ScanHit(
                "com.android.vending",
                listOf("com.android.vending"),
                "com.android.shell",
            )
        val signal = IntegrityDetectionModule.installerSignals(hit, emptyMap()).single()
        assertEquals("com.android.shell", signal.evidence["initiating"])
        val plain = InstallerOriginCheck.ScanHit(null, listOf("com.android.vending"))
        assertEquals(null, IntegrityDetectionModule.installerSignals(plain, emptyMap()).single().evidence["initiating"])
    }
}
