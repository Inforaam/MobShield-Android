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

import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import io.mobshield.detect.integrity.internal.ApkSigningBlock
import io.mobshield.detect.integrity.internal.DigestUtil
import java.io.File
import java.security.MessageDigest

class SignatureCheck(
    private val packageName: String,
    private val expectedSigners: List<String>,
    private val certificateDigestsProvider: () -> List<String>,
    private val apkCertificateDigestsProvider: () -> List<String>? = { null },
) {
    fun scan(): ScanHit? {
        if (expectedSigners.isEmpty()) {
            return null
        }
        val digests = certificateDigestsProvider().map(DigestUtil::normalizeHex).toSet()
        if (digests.isEmpty()) {
            return ScanHit(expected = expectedSigners, actual = emptyList(), reason = "no_certificates")
        }
        val expected = expectedSigners.map(DigestUtil::normalizeHex).toSet()
        if (digests.intersect(expected).isEmpty()) {
            return ScanHit(expected = expectedSigners, actual = digests.toList(), reason = "mismatch")
        }
        val apkDigests = apkCertificateDigestsProvider()?.map(DigestUtil::normalizeHex)?.toSet()
        if (apkDigests.isNullOrEmpty() || apkDigests.intersect(expected).isNotEmpty()) {
            return null
        }
        return ScanHit(expected = expectedSigners, actual = apkDigests.toList(), reason = "apk_signer_mismatch")
    }

    data class ScanHit(
        val expected: List<String>,
        val actual: List<String>,
        val reason: String,
    )

    companion object {
        fun certificateDigests(
            packageManager: PackageManager,
            packageName: String,
        ): List<String> =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                certificateDigestsApi28(packageManager, packageName)
            } else {
                certificateDigestsLegacy(packageManager, packageName)
            }

        @SuppressLint("NewApi", "InlinedApi")
        private fun certificateDigestsApi28(
            packageManager: PackageManager,
            packageName: String,
        ): List<String> {
            @Suppress("DEPRECATION")
            val packageInfo =
                packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES,
                )
            val signingInfo = packageInfo.signingInfo ?: return emptyList()
            val signatures: Array<Signature> =
                if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners ?: emptyArray()
                } else {
                    signingInfo.signingCertificateHistory ?: emptyArray()
                }
            return digestSignatures(signatures)
        }

        @Suppress("DEPRECATION")
        private fun certificateDigestsLegacy(
            packageManager: PackageManager,
            packageName: String,
        ): List<String> {
            val packageInfo =
                packageManager.getPackageInfo(
                    packageName,
                    PackageManager.GET_SIGNATURES,
                )
            val signatures = packageInfo.signatures ?: return emptyList()
            return digestSignatures(signatures)
        }

        /** Digests of the certificates in the APK's signing block that the platform verifies at [sdkInt]. */
        fun apkCertificateDigests(
            apk: File,
            sdkInt: Int,
        ): List<String>? {
            val blocks = ApkSigningBlock.read(apk) ?: return null
            return ApkSigningBlock.trustedCertificates(blocks, sdkInt)?.map(DigestUtil::sha256Hex)
        }

        private fun digestSignatures(signatures: Array<Signature>): List<String> {
            val digest = MessageDigest.getInstance("SHA-256")
            return signatures.map { signature ->
                DigestUtil.sha256Hex(digest.digest(signature.toByteArray()))
            }
        }
    }
}
