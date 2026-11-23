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

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import io.mobshield.core.DetectionModule
import io.mobshield.core.MobShieldConfig
import io.mobshield.core.Signal
import io.mobshield.core.SignalTuning
import io.mobshield.detect.integrity.internal.DigestUtil
import io.mobshield.detect.integrity.internal.NativeLibraryLocator
import io.mobshield.detect.integrity.internal.SuccessCache
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withTimeout

class IntegrityDetectionModule(
    context: Context,
    private val config: MobShieldConfig,
    private val detectionTuning: Map<String, SignalTuning> = config.detectionTuning,
    private val scanTimeoutMs: Long = DEFAULT_SCAN_TIMEOUT_MS,
    private val digestTimeoutMs: Long = DEFAULT_DIGEST_TIMEOUT_MS,
) : DetectionModule {
    private val appContext = context.applicationContext
    private val packageName = appContext.packageName
    private val packageManager = appContext.packageManager

    private val apkDigest = SuccessCache<String>()
    private val nativeLibrary = SuccessCache<NativeLibChecksumCheck.NativeLibrary>()
    private val nativeLibDigest = SuccessCache<String>()

    private val signatureCheck =
        SignatureCheck(
            packageName = packageName,
            expectedSigners = config.expectedSigners,
            certificateDigestsProvider = {
                SignatureCheck.certificateDigests(packageManager, packageName)
            },
        )
    private val packageIdCheck = PackageIdCheck(config.expectedPackageId, packageName)
    private val installerCheck =
        InstallerOriginCheck(
            allowedInstallSources = config.allowedInstallSources,
            installingPackageProvider = { readInstallingPackageName() },
        )
    private val apkChecksumCheck =
        ApkChecksumCheck(
            expectedApkSha256 = config.expectedApkSha256,
            checksumProvider = {
                apkDigest.get {
                    ApkChecksumCheck.requestWholeApkSha256(packageManager, packageName, digestTimeoutMs)
                }
            },
        )
    private val nativeLibChecksumCheck =
        NativeLibChecksumCheck(
            expectedNativeLibSha256 = config.expectedNativeLibSha256,
            expectedByAbi = config.expectedNativeLibSha256ByAbi,
            libraryProvider = { nativeLibrary.get(::locateCoreLibrary) },
            digestComputer = { library ->
                nativeLibDigest.get {
                    runCatching { library.open().use(DigestUtil::sha256HexStream) }.getOrNull()
                }
            },
        )

    override val name: String = MODULE_NAME

    override val criticality: Int = CRITICALITY

    override suspend fun scan(): List<Signal> =
        coroutineScope {
            val results =
                buildList {
                    if (config.expectedSigners.isNotEmpty()) {
                        add(async { runCheck(CHECK_SIGNATURE, scanTimeoutMs, ::scanSignature) })
                    }
                    if (config.expectedPackageId != null) {
                        add(async { runCheck(CHECK_PACKAGE_ID, scanTimeoutMs, ::scanPackageId) })
                    }
                    add(async { runCheck(CHECK_INSTALLER, scanTimeoutMs, ::scanInstaller) })
                    if (config.expectedApkSha256 != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        add(async { runCheck(CHECK_APK_CHECKSUM, digestTimeoutMs, ::scanApkChecksum) })
                    }
                    if (config.expectedNativeLibSha256 != null || config.expectedNativeLibSha256ByAbi.isNotEmpty()) {
                        add(async { runCheck(CHECK_NATIVE_LIB_CHECKSUM, digestTimeoutMs, ::scanNativeLibChecksum) })
                    }
                }.awaitAll()
            results.flatMap { it.signals } + listOfNotNull(unavailableSignal(results, detectionTuning))
        }

    private fun scanSignature(): CheckResult {
        val hit = signatureCheck.scan() ?: return CheckResult.CLEAN
        return CheckResult.of(
            IntegritySignalDefaults.buildSignal(
                IntegritySignalDefaults.SIGNATURE,
                mapOf(
                    "reason" to hit.reason,
                    "expectedCount" to hit.expected.size.toString(),
                    "actual" to hit.actual.joinToString(","),
                ),
                detectionTuning,
            ),
        )
    }

    private fun scanPackageId(): CheckResult = CheckResult(packageIdSignals(packageIdCheck.scan(), detectionTuning))

    private fun scanInstaller(): CheckResult = CheckResult(installerSignals(installerCheck.scan(), detectionTuning))

    private fun scanApkChecksum(): CheckResult {
        val hit = apkChecksumCheck.scan() ?: return CheckResult.CLEAN
        if (hit.actual == null) {
            return CheckResult.unavailable(CHECK_APK_CHECKSUM, hit.reason)
        }
        return CheckResult.of(
            IntegritySignalDefaults.buildSignal(
                IntegritySignalDefaults.APK_CHECKSUM,
                mapOf(
                    "reason" to hit.reason,
                    "expected" to DigestUtil.normalizeHex(hit.expected),
                    "actual" to DigestUtil.normalizeHex(hit.actual),
                ),
                detectionTuning,
            ),
        )
    }

    private fun scanNativeLibChecksum(): CheckResult {
        val hit = nativeLibChecksumCheck.scan() ?: return CheckResult.CLEAN
        if (hit.actual == null || hit.expected == null) {
            return CheckResult.unavailable(CHECK_NATIVE_LIB_CHECKSUM, hit.reason)
        }
        return CheckResult.of(
            IntegritySignalDefaults.buildSignal(
                IntegritySignalDefaults.NATIVE_LIB_CHECKSUM,
                mapOf(
                    "reason" to hit.reason,
                    "path" to (hit.path ?: "null"),
                    "abi" to (hit.abi ?: "null"),
                    "expected" to DigestUtil.normalizeHex(hit.expected),
                    "actual" to DigestUtil.normalizeHex(hit.actual),
                ),
                detectionTuning,
            ),
        )
    }

    private fun locateCoreLibrary(): NativeLibChecksumCheck.NativeLibrary? {
        val info = appContext.applicationInfo
        val abis = if (Process.is64Bit()) Build.SUPPORTED_64_BIT_ABIS else Build.SUPPORTED_32_BIT_ABIS
        return NativeLibraryLocator.locate(
            libraryName = NativeLibChecksumCheck.CORE_LIBRARY_NAME,
            nativeLibraryDir = info.nativeLibraryDir,
            apkPaths = listOfNotNull(info.sourceDir) + info.splitSourceDirs.orEmpty(),
            abis = abis.toList(),
        )
    }

    private fun readInstallingPackageName(): String? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                packageManager.getInstallSourceInfo(packageName).installingPackageName
            } catch (_: PackageManager.NameNotFoundException) {
                null
            }
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstallerPackageName(packageName)
        }

    internal class CheckResult(
        val signals: List<Signal>,
        val unavailable: String? = null,
    ) {
        companion object {
            val CLEAN = CheckResult(emptyList())

            fun of(signal: Signal) = CheckResult(listOf(signal))

            fun unavailable(
                check: String,
                reason: String,
            ) = CheckResult(emptyList(), "$check:$reason")
        }
    }

    companion object {
        const val MODULE_NAME = "integrity"
        const val CRITICALITY = 100
        const val DEFAULT_SCAN_TIMEOUT_MS = 500L
        const val DEFAULT_DIGEST_TIMEOUT_MS = ApkChecksumCheck.DEFAULT_TIMEOUT_MS

        internal const val CHECK_SIGNATURE = "signature"
        internal const val CHECK_PACKAGE_ID = "package_id"
        internal const val CHECK_INSTALLER = "installer"
        internal const val CHECK_APK_CHECKSUM = "apk_checksum"
        internal const val CHECK_NATIVE_LIB_CHECKSUM = "native_lib_checksum"

        internal suspend fun runCheck(
            check: String,
            timeoutMs: Long,
            block: () -> CheckResult,
        ): CheckResult =
            try {
                withTimeout(timeoutMs) { runInterruptible(Dispatchers.IO) { block() } }
            } catch (_: TimeoutCancellationException) {
                CheckResult.unavailable(check, "timeout")
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                CheckResult.unavailable(check, "error")
            }

        internal fun unavailableSignal(
            results: List<CheckResult>,
            tuning: Map<String, SignalTuning>,
        ): Signal? {
            val unavailable = results.mapNotNull { it.unavailable }
            if (unavailable.isEmpty()) {
                return null
            }
            return IntegritySignalDefaults.buildSignal(
                IntegritySignalDefaults.CHECK_UNAVAILABLE,
                mapOf("checks" to unavailable.sorted().joinToString(",")),
                tuning,
            )
        }

        internal fun installerSignals(
            hit: InstallerOriginCheck.ScanHit?,
            tuning: Map<String, SignalTuning>,
        ): List<Signal> {
            if (hit == null) {
                return emptyList()
            }
            return listOf(
                IntegritySignalDefaults.buildSignal(
                    IntegritySignalDefaults.INSTALLER,
                    mapOf(
                        "installer" to (hit.installer ?: "null"),
                        "allowed" to hit.allowed.joinToString(","),
                    ),
                    tuning,
                ),
            )
        }

        internal fun packageIdSignals(
            hit: PackageIdCheck.ScanHit?,
            tuning: Map<String, SignalTuning>,
        ): List<Signal> {
            if (hit == null) {
                return emptyList()
            }
            return listOf(
                IntegritySignalDefaults.buildSignal(
                    IntegritySignalDefaults.PACKAGE_ID,
                    mapOf("expected" to hit.expected, "actual" to hit.actual),
                    tuning,
                ),
            )
        }
    }
}
