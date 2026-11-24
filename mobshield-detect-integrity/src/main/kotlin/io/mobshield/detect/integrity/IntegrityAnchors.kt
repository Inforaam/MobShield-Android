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
import io.mobshield.detect.integrity.internal.NativeLibraryLocator

/**
 * The integrity values of the running app, for filling in [io.mobshield.core.MobShieldConfig].
 *
 * Read them from a build installed the way users get it, for example from a Play internal test
 * track: Play App Signing installs the app with Play's signing certificate, not your upload key.
 * [read] does file I/O, so call it off the main thread.
 */
class IntegrityAnchors(
    val packageName: String,
    /** SHA-256 of the signing certificates reported by `PackageManager`, including rotated ones. */
    val signerSha256: List<String>,
    /** SHA-256 of `libmobshieldcore.so` for each ABI present in the installed APKs. */
    val nativeLibSha256ByAbi: Map<String, String>,
    val installingPackage: String?,
) {
    /** A `MobShieldConfig.builder()` snippet with these values. */
    fun toConfigSnippet(): String =
        buildString {
            appendLine("MobShieldConfig.builder()")
            appendLine("    .expectedPackageId(\"$packageName\")")
            if (signerSha256.isNotEmpty()) {
                appendLine("    .expectedSigners(listOf(${signerSha256.joinToString(", ") { "\"$it\"" }}))")
            }
            if (nativeLibSha256ByAbi.isNotEmpty()) {
                appendLine("    .expectedNativeLibSha256ByAbi(")
                appendLine("        mapOf(")
                nativeLibSha256ByAbi.forEach { (abi, digest) -> appendLine("            \"$abi\" to \"$digest\",") }
                appendLine("        ),")
                appendLine("    )")
            }
            append("    .build()")
        }

    companion object {
        @JvmStatic
        fun read(context: Context): IntegrityAnchors {
            val appContext = context.applicationContext
            val packageName = appContext.packageName
            val packageManager = appContext.packageManager
            val info = appContext.applicationInfo
            val apkPaths = listOfNotNull(info.sourceDir) + info.splitSourceDirs.orEmpty()
            return IntegrityAnchors(
                packageName = packageName,
                signerSha256 =
                    runCatching {
                        SignatureCheck.certificateDigests(
                            packageManager,
                            packageName,
                        )
                    }.getOrDefault(emptyList()),
                nativeLibSha256ByAbi =
                    NativeLibraryLocator.digestsByAbi(
                        NativeLibChecksumCheck.CORE_LIBRARY_NAME,
                        apkPaths,
                    ),
                installingPackage = installingPackage(packageManager, packageName),
            )
        }

        private fun installingPackage(
            packageManager: PackageManager,
            packageName: String,
        ): String? =
            runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    packageManager.getInstallSourceInfo(packageName).installingPackageName
                } else {
                    @Suppress("DEPRECATION")
                    packageManager.getInstallerPackageName(packageName)
                }
            }.getOrNull()
    }
}
