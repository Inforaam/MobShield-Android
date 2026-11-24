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

/**
 * Compares `ApplicationInfo.sourceDir` with the app's own `base.apk` that the process has mapped,
 * as listed in `/proc/self/maps`.
 */
class ApkPathCheck(
    private val packageName: String,
    private val sourceDirProvider: () -> String?,
    private val mapsProvider: () -> Sequence<String>,
) {
    fun scan(): ScanHit? {
        val sourceDir = sourceDirProvider() ?: return null
        val mapped = mappedBaseApks().toSet()
        if (mapped.isEmpty() || sourceDir in mapped) {
            return null
        }
        return ScanHit(sourceDir = sourceDir, mapped = mapped.sorted())
    }

    private fun mappedBaseApks(): Sequence<String> =
        mapsProvider()
            .mapNotNull { line -> line.indexOf('/').takeIf { it >= 0 }?.let { line.substring(it).trim() } }
            .filter { path -> path.endsWith("/$BASE_APK") && isOwnPackageDir(path.removeSuffix("/$BASE_APK")) }

    private fun isOwnPackageDir(dir: String): Boolean {
        val name = dir.substringAfterLast('/')
        return name == packageName || name.startsWith("$packageName-")
    }

    data class ScanHit(
        val sourceDir: String,
        val mapped: List<String>,
    )

    private companion object {
        const val BASE_APK = "base.apk"
    }
}
