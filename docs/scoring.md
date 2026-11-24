# How MobShield scores threats

This page describes how signals become threat scores and severities, what the default numbers mean,
and what they do not mean. The Android and iOS libraries implement the same model and share the
same default thresholds and correlation groups.

## From signals to a score

Each detector check emits a **signal** with a name, a **weight** (0-100, how serious the finding is
if true) and a **confidence** (0-100, how sure the check is). Signals are routed to a threat type by
name prefix (for example `android.root.*` and `ios.jb.*` go to `PRIVILEGED_ACCESS`; any name
containing `.hook.` goes to `HOOK_FRAMEWORK`). Names that match no prefix are ignored, and
MobShield logs a warning (tag `MobShield`) the first time it sees each one. `detectionTuning` and
`signalGroups` entries whose names match no prefix are logged when MobShield starts.

For each threat type, the score is computed like this:

1. Each signal contributes `weight x confidence / 100` points.
2. Signals that share a **correlation group** are combined with noisy-OR:
   `100 x (1 - (1 - a/100) x (1 - b/100) x ...)`. A group is never lower than its strongest member
   and never higher than the plain sum of its members.
3. Groups and ungrouped signals are added together.
4. The total is capped at 100 and truncated to an integer (80.75 becomes 80).

The arithmetic is done in integer hundredths of a point, rounding the noisy-OR complement up at
each step so a group is never overstated. Results are exact and identical on both platforms.

### Why correlation groups exist

Adding signals treats them as independent observations. Some are not: two checks may read the same
file, or detect the same tool through its different artifacts. Adding them counts one finding
several times. For example, `common.hook.frida_maps` and `android.hook.suspicious_library` both
scan `/proc/self/maps` for the same Frida and Xposed library names; when both fire, the plain sum
was 99 even though only one piece of evidence was observed.

Noisy-OR keeps corroboration (two checks agreeing still raises the score) but with diminishing
returns. Signals that are not in a group still add, exactly as before.

| Group | Signals | What they share |
|---|---|---|
| `hook.frida` | `common.hook.frida_maps`, `common.hook.prologue`, `android.hook.frida_port`, `android.hook.thread_name`, `android.hook.suspicious_library`, `ios.hook.frida_thread`, `ios.hook.frida_symbols`, `ios.hook.frida_port` | Artifacts of one Frida agent, gadget or server. `frida_maps` and `suspicious_library` read the same `/proc/self/maps` lines. |
| `hook.xposed` | `android.hook.art_dex`, `android.hook.xposed`, `android.hook.stack_leak` | The Xposed / LSPosed bridge, seen through the class loader and stack traces. |
| `root.mounts` | `android.root.mount_namespace`, `android.root.overlayfs` | The kernel mount tables (`/proc/1/mountinfo`, `/proc/self/mountinfo`, `/proc/self/mounts`). |
| `root.su_paths` | `android.root.path_probe`, `android.root.errno_deviation` | Probes of the same `su` and root paths. |
| `debug.tracer` | `android.debug.tracerpid`, `android.debug.ptrace` | One attached tracer: `TracerPid` in `/proc/self/status`, and `PTRACE_TRACEME` failing because the process is already traced. |
| `jb.dyld_images` | `ios.jb.dyld_image`, `ios.jb.dyld_header` | The same list of loaded images, read by name and by Mach-O header. |

`common.hook.prologue` detects inline hooks from any framework, not only Frida. It is in the Frida
group because Frida instruments through inline hooks, so the two move together when Frida is
present; on its own it scores exactly as before.

Example: Frida maps (75/85) plus Frida threads (70/80) used to add to 100. As a group they score 84,
which is still CRITICAL for `HOOK_FRAMEWORK` (critical at 65).

You can replace the table with `signalGroups` in the configuration (signal name to any group id).
An empty map turns grouping off and restores plain addition.

## From score to severity

Each threat type has a warning threshold *W* and an optional critical threshold *C*:

| Condition | Severity |
|---|---|
| score >= *C* | CRITICAL |
| score >= *W* | HIGH |
| score >= *W* / 2 | MEDIUM |
| score >= *W* / 4 | LOW |
| otherwise | INFO (not emitted) |

Division is integer division. `DEVELOPER_MODE` and `ADB_ENABLED` are informational: they have no
critical threshold, report HIGH at or above *W* and INFO below it, and are dropped below *W* / 2.

| Threat type | Warning | Critical |
|---|---|---|
| `PRIVILEGED_ACCESS` (root / jailbreak) | 40 | 70 |
| `HOOK_FRAMEWORK` | 35 | 65 |
| `DEBUGGER` | 30 | 60 |
| `EMULATOR` | 25 | 55 |
| `AUTOMATION` | 30 | 60 |
| `APP_INTEGRITY` | 50 | 80 |
| `UNOFFICIAL_STORE` | 20 | 50 |
| `DEVELOPER_MODE`, `ADB_ENABLED` | 15 | none |

## What one signal can do on its own

A critical score means different things for different threat types. Some single checks reach
CRITICAL by themselves; for others, CRITICAL needs several signals to agree. This table lists each
default Android signal when it is the only signal of its threat type. It is enforced by the
`SingleSignalSeverityTest` in each detector module, so it cannot drift from the code.

| Signal | Weight / confidence | Score | Severity |
|---|---|---|---|
| **Root** (`PRIVILEGED_ACCESS`, warning 40, critical 70) | | | |
| `android.root.mount_namespace` | 75 / 85 | 63 | HIGH |
| `android.root.kernelsu_sysfs` | 75 / 85 | 63 | HIGH |
| `android.root.magisk_uds` | 70 / 80 | 56 | HIGH |
| `android.root.zygisk_maps` | 70 / 80 | 56 | HIGH |
| `android.root.overlayfs` | 65 / 75 | 48 | HIGH |
| `android.root.errno_deviation` | 60 / 70 | 42 | HIGH |
| `android.root.dangerous_packages` | 55 / 70 | 38 | MEDIUM |
| `android.root.path_probe` | 25 / 35 | 8 | no event |
| `android.root.props` | 20 / 30 | 6 | no event |
| **Hooks** (`HOOK_FRAMEWORK`, warning 35, critical 65) | | | |
| `android.hook.frida_port` | 85 / 95 | 80 | CRITICAL |
| `common.hook.prologue` | 80 / 90 | 72 | CRITICAL |
| `common.hook.frida_maps` | 75 / 85 | 63 | HIGH |
| `android.hook.art_dex` | 75 / 85 | 63 | HIGH |
| `android.hook.thread_name` | 70 / 80 | 56 | HIGH |
| `android.hook.xposed` | 70 / 80 | 56 | HIGH |
| `android.hook.stack_leak` | 65 / 75 | 48 | HIGH |
| `android.hook.suspicious_library` | 55 / 65 | 35 | HIGH |
| **Debugger** (`DEBUGGER`, warning 30, critical 60) | | | |
| `android.debug.waiting` | 90 / 95 | 85 | CRITICAL |
| `android.debug.tracerpid` | 85 / 90 | 76 | CRITICAL |
| `android.debug.ptrace` | 80 / 85 | 68 | CRITICAL |
| `android.debug.timing` | 65 / 70 | 45 | HIGH |
| `android.debug.app_debuggable` | 70 / 60 | 42 | HIGH |
| `android.adb.enabled` (`ADB_ENABLED`) | 30 / 40 | 12 | INFO |
| **Emulator and automation** (`EMULATOR` 25/55, `AUTOMATION` 30/60) | | | |
| `android.env.qemu_device` | 28 / 75 | 21 | MEDIUM |
| `android.automation.framework` | 30 / 70 | 21 | MEDIUM |
| `android.env.cpu_goldfish` | 24 / 70 | 16 | MEDIUM |
| `android.env.qemu_props` | 22 / 65 | 14 | MEDIUM |
| `android.env.build_fingerprint` | 20 / 60 | 12 | MEDIUM |
| `android.env.sensor_count` | 18 / 55 | 9 | LOW |
| **Integrity and store** (`APP_INTEGRITY` 50/80, `UNOFFICIAL_STORE` 20/50) | | | |
| `android.integrity.signature` | 90 / 95 | 85 | CRITICAL |
| `android.integrity.apk_checksum` | 85 / 90 | 76 | HIGH |
| `android.integrity.package_id` | 85 / 90 | 76 | HIGH |
| `android.integrity.apk_path` | 70 / 80 | 56 | HIGH |
| `android.integrity.native_lib_checksum` | 80 / 85 | 68 | HIGH |
| `android.integrity.check_unavailable` | 30 / 40 | 12 | LOW |
| `android.store.installer` | 25 / 45 | 11 | MEDIUM |

What this means in practice:

- **Root never reaches CRITICAL from one signal.** The strongest single root signals score 63. Two
  independent root signals are needed, for example Magisk's socket (56) plus a mount-namespace
  difference (63), which adds to 100.
- **A hook or debugger can reach CRITICAL from one signal**: the Frida port, an inline-hook
  prologue change, a tracer, or the app waiting for a debugger.
- **No single emulator signal reaches HIGH**, so a developer's emulator stays below the warning
  threshold unless several emulator checks agree.
- **A wrong signing certificate is CRITICAL on its own**; a changed APK or native-library checksum is
  HIGH.
- **Only a signal rated HIGH or CRITICAL here can trigger termination.** Weak hints that add up to
  HIGH or CRITICAL are reported but never end the process; see [termination.md](termination.md).

This asymmetry is a consequence of the default weights, not a calibrated judgment (see below). If it
does not suit your app, change `thresholds` or `detectionTuning`.

## What the numbers are, and are not

- **The weights and confidences are hand-assigned defaults.** They have not been fitted to data,
  and the repository does not record how each value was chosen.
- **No false-positive or detection rates are published.** The project does not yet have
  measurements across real devices, vendor ROMs, root and jailbreak tools, or Frida setups.
- **A score is not a probability.** "Score 70" does not mean "70% likely to be rooted". Severities
  are bands chosen to fit the default weights.
- **Correlation groups are also judgment.** They are based on what each check reads, documented
  above, but the strength of the correlation has not been measured.

Treat the defaults as a starting point. Before you act on a severity (in particular before enabling
a termination policy), observe the events your own users produce and adjust `thresholds`,
`detectionTuning` or `signalGroups`.

### Help calibrate them

Reports from real devices are the only way these numbers can improve. Useful reports include:

- device model, OS version and ROM or build;
- the root, jailbreak or instrumentation tool and its version, or "clean device";
- the signals emitted (names, scores and severities from `onThreat`);
- whether the result was correct.

Open an issue with these details. Report a detection **bypass** privately through the repository's
security policy instead.

## Changes in this version

- Correlated signals are combined with noisy-OR instead of added (`signalGroups`, on by default).
- Scores are computed with exact integer arithmetic; a score that is a whole number can no longer be
  truncated one point low by floating-point error.
- `signalSetVersion` is now `signals-2026.11.0`, so a backend can tell which scoring produced a
  report.
