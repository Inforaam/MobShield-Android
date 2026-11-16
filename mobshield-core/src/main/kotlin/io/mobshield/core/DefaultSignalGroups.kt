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

/**
 * Default correlation groups for built-in signals, keyed by signal name.
 *
 * Signals in the same group read the same evidence or detect the same tool, so they are not
 * independent observations. [SignalAggregator] combines a group with diminishing returns
 * (noisy-OR) instead of adding its members, which stops one artifact from being counted several
 * times. Signals without a group add independently, as before. See `docs/scoring.md`.
 *
 * The table is shared with the iOS library and contains names from both platforms.
 */
object DefaultSignalGroups {
    /** Frida agent, gadget or server: maps, threads, symbols, port and inline hooks. */
    const val HOOK_FRIDA = "hook.frida"

    /** Xposed / LSPosed bridge visible to the class loader and in stack traces. */
    const val HOOK_XPOSED = "hook.xposed"

    /** Mount-table changes read from `/proc/1/mountinfo`, `/proc/self/mountinfo` and `/proc/self/mounts`. */
    const val ROOT_MOUNTS = "root.mounts"

    /** `stat()`-based probes of the same `su` and root paths. */
    const val ROOT_SU_PATHS = "root.su_paths"

    /** An attached tracer, seen as `TracerPid` and as a failing `PTRACE_TRACEME`. */
    const val DEBUG_TRACER = "debug.tracer"

    /** iOS loaded-image list read twice, by name and by Mach-O header. */
    const val JB_DYLD_IMAGES = "jb.dyld_images"

    val map: Map<String, String> =
        mapOf(
            "common.hook.frida_maps" to HOOK_FRIDA,
            "common.hook.prologue" to HOOK_FRIDA,
            "android.hook.frida_port" to HOOK_FRIDA,
            "android.hook.thread_name" to HOOK_FRIDA,
            "android.hook.suspicious_library" to HOOK_FRIDA,
            "ios.hook.frida_thread" to HOOK_FRIDA,
            "ios.hook.frida_symbols" to HOOK_FRIDA,
            "ios.hook.frida_port" to HOOK_FRIDA,
            "android.hook.art_dex" to HOOK_XPOSED,
            "android.hook.xposed" to HOOK_XPOSED,
            "android.hook.stack_leak" to HOOK_XPOSED,
            "android.root.mount_namespace" to ROOT_MOUNTS,
            "android.root.overlayfs" to ROOT_MOUNTS,
            "android.root.path_probe" to ROOT_SU_PATHS,
            "android.root.errno_deviation" to ROOT_SU_PATHS,
            "android.debug.tracerpid" to DEBUG_TRACER,
            "android.debug.ptrace" to DEBUG_TRACER,
            "ios.jb.dyld_image" to JB_DYLD_IMAGES,
            "ios.jb.dyld_header" to JB_DYLD_IMAGES,
        )
}
