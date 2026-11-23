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

import android.content.Context
import io.mobshield.core.internal.MobShieldEngine
import io.mobshield.core.internal.NativeBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.util.concurrent.atomic.AtomicReference

/** Public entry point for MobShield on Android. */
object MobShield {
    const val SIGNAL_SET_VERSION = "signals-2026.11.0"

    private val engineRef = AtomicReference<MobShieldEngine?>(null)
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /**
     * Starts MobShield: loads native core, schedules registered [DetectionModule] scans,
     * and delivers callbacks on the listener.
     */
    @JvmStatic
    fun start(
        context: Context,
        config: MobShieldConfig,
        listener: MobShieldListener,
    ) {
        context.applicationContext
        NativeBridge.ensureLoaded()
        stop()
        val engine =
            MobShieldEngine(
                config = config,
                listener = listener,
                resolveModules = { ModuleRegistry.getAll() },
                scope = appScope,
                signalSetVersion = SIGNAL_SET_VERSION,
            )
        engineRef.set(engine)
        engine.start()
    }

    /** Stops active scans and resets runtime state. */
    @JvmStatic
    fun stop() {
        engineRef.getAndSet(null)?.stop()
    }

    /** Returns the latest posture snapshot. */
    @JvmStatic
    fun getState(): MobShieldState =
        engineRef.get()?.getState()
            ?: MobShieldState(
                riskLevel = RiskLevel.NONE,
                activeThreats = emptyList(),
                lastScanMs = 0L,
                signalSetVersion = SIGNAL_SET_VERSION,
                running = false,
            )

    /** Events from the most recent completed scan wave. */
    @JvmStatic
    fun getLastEvents(): List<ThreatEvent> = engineRef.get()?.getLastEvents() ?: emptyList()

    /** A snapshot report of the latest scan wave's posture, suitable for sending to a backend. */
    @JvmStatic
    fun currentReport(schemaVersion: String = ThreatReport.CURRENT_SCHEMA_VERSION): ThreatReport =
        MobShieldReporter.makeReport(getState(), getLastEvents(), getBuildId(), schemaVersion)

    /**
     * The current report, answering [challenge], for binding to a Play Integrity verdict: send
     * `MobShieldReporter.canonicalJson(report)` to your backend and pass
     * `MobShieldReporter.requestHash(json)` as the integrity request's `requestHash`.
     */
    @JvmStatic
    fun currentReport(challenge: ByteArray): ThreatReport =
        MobShieldReporter.makeReport(getState(), getLastEvents(), getBuildId(), challenge = challenge)

    /**
     * The current report, answering the server-issued [challenge], signed by a new hardware-backed
     * key whose Key Attestation chain is bound to the same challenge. Send the result to your backend
     * and verify it there as described in `docs/report-attestation.md`.
     *
     * Blocks while the Keystore creates the key, which can take seconds: call it off the main thread.
     *
     * @throws ReportAttestationException if the device cannot create or use an attested key.
     */
    @JvmStatic
    @JvmOverloads
    fun currentAttestedReport(
        challenge: ByteArray,
        attester: ReportAttester = AndroidKeystoreReportAttester(),
    ): AttestedThreatReport = MobShieldReporter.attest(currentReport(challenge), challenge, attester)

    /**
     * The current report as canonical JSON plus an HMAC-SHA256 signature under [key].
     *
     * The key ships inside the app, so anyone who can read or hook the app can sign a clean report
     * with it, and the report can be replayed. Use [currentAttestedReport] instead.
     */
    @Deprecated(
        "An HMAC key shipped in the app cannot prove where a report came from. " +
            "Use currentAttestedReport(challenge); see docs/report-attestation.md.",
        ReplaceWith("currentAttestedReport(challenge)"),
    )
    @JvmStatic
    @Suppress("DEPRECATION")
    fun currentSignedReport(key: ByteArray): SignedThreatReport = MobShieldReporter.sign(currentReport(), key)

    /** Native and API version string. */
    @JvmStatic
    fun getVersion(): String {
        NativeBridge.ensureLoaded()
        return NativeBridge.getVersion()
    }

    /** Native build identifier injected at compile time. */
    @JvmStatic
    fun getBuildId(): String {
        NativeBridge.ensureLoaded()
        return NativeBridge.getBuildId()
    }

    /** Native integrity self-check; nonzero indicates a healthy core. */
    @JvmStatic
    fun selfCheck(): Int {
        NativeBridge.ensureLoaded()
        return NativeBridge.selfCheck()
    }

    internal fun resetForTests() {
        stop()
        ModuleRegistry.clear()
    }
}
