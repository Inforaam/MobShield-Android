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

class InstallerOriginCheck(
    private val allowedInstallSources: Set<String>,
    private val installingPackageProvider: () -> String?,
    private val initiatingPackageProvider: () -> String? = { null },
) {
    fun scan(): ScanHit? {
        val installer = installingPackageProvider()
        if (installer == null || installer !in allowedInstallSources) {
            return ScanHit(installer = installer, allowed = allowedInstallSources.sorted())
        }
        val initiating = initiatingPackageProvider()
        if (initiating == null || initiating == installer || initiating in allowedInstallSources) {
            return null
        }
        return ScanHit(installer = installer, allowed = allowedInstallSources.sorted(), initiating = initiating)
    }

    /** [initiating] is set when the installer is allowed but the app that started the install is not. */
    data class ScanHit(
        val installer: String?,
        val allowed: List<String>,
        val initiating: String? = null,
    )
}
