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

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ApkPathCheckTest {
    private val pkg = "com.example.app"
    private val installed = "/data/app/~~abc==/com.example.app-xyz==/base.apk"

    private fun maps(vararg paths: String) =
        paths.map { "7f00000000-7f00001000 r--p 00000000 fd:05 1234                       $it" }.asSequence()

    @Test
    fun sourceDirIsMapped_returnsNull() {
        val check = ApkPathCheck(pkg, { installed }, { maps("/system/lib64/libc.so", installed) })
        assertNull(check.scan())
    }

    @Test
    fun sourceDirDiffersFromMappedOwnApk_returnsHit() {
        val elsewhere = "/data/user/0/com.example.app/cache/origin.apk"
        val hit = ApkPathCheck(pkg, { elsewhere }, { maps(installed) }).scan()
        assertEquals(elsewhere, hit?.sourceDir)
        assertEquals(listOf(installed), hit?.mapped)
    }

    @Test
    fun otherAppsApks_areIgnored() {
        val webView = "/data/app/~~def==/com.google.android.webview-uvw==/base.apk"
        val similar = "/data/app/~~ghi==/com.example.app.debug-rst==/base.apk"
        assertNull(ApkPathCheck(pkg, { installed }, { maps(webView, similar) }).scan())
    }

    @Test
    fun legacyDirectoryLayout_isRecognised() {
        val legacy = "/data/app/com.example.app-1/base.apk"
        assertNull(ApkPathCheck(pkg, { legacy }, { maps(legacy) }).scan())
        assertEquals(legacy, ApkPathCheck(pkg, { "/tmp/other.apk" }, { maps(legacy) }).scan()?.mapped?.single())
    }

    @Test
    fun ownApkNotMapped_returnsNull() {
        assertNull(ApkPathCheck(pkg, { installed }, { maps("/system/framework/framework-res.apk") }).scan())
    }
}
