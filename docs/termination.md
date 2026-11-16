# Process termination

MobShield runs in detect-only mode by default: it reports threats and never ends your process. This
page covers what happens when you opt in to termination, why the rules are what they are, and what
termination can and cannot do for you.

## When the process is terminated

With `detectOnly(false)` and a `TerminationPolicy` other than `NONE`, a scan ends the process when
any threat event meets **all** of these conditions:

1. **Severity.** `EXIT_ON_BYPASS` needs HIGH or CRITICAL; `EXIT_ON_CRITICAL` needs CRITICAL.
2. **Corroboration.** At least one of the event's signals reaches HIGH **on its own**, scored as if
   it were the only signal of its threat type.
3. **Type.** The event's threat type is in `terminateOn` (default: every type).

Your listener receives every event and `onAllChecksFinished` before the process is terminated.
Events that fail condition 2 or 3 are still reported exactly as before; they just cannot end the
process.

## Why corroboration is required

A threat's score adds up evidence from several checks (see [scoring.md](scoring.md)). That is useful
for reporting, but it means weak hints can reach a severity none of them reaches alone. For example,
three weak root hints a custom ROM can trip:

| Signal | Score alone |
|---|---|
| `android.root.dangerous_packages` | 38 (MEDIUM) |
| `android.root.path_probe` | 8 (no event) |
| `android.root.props` | 6 (no event) |
| **Together** | **53 (HIGH)** |

Before this change, `EXIT_ON_BYPASS` killed the app on that combination. None of these checks is
evidence of an active attack by itself, and the weights are not calibrated against real devices, so
a user on an unusual but legitimate device could be locked out of the app. Now the event is still
reported as HIGH, but it terminates only if a signal such as `android.root.mount_namespace` (63) is
also present.

## What can terminate, with the default weights

The single-signal table in [scoring.md](scoring.md#what-one-signal-can-do-on-its-own) shows each
signal's severity on its own; a signal rated HIGH or CRITICAL there can corroborate termination. In
practice:

- **Hooks, debugger, app integrity.** Every default signal is HIGH or CRITICAL on its own, so these
  terminate as before.
- **Root.** Six signals are strong on their own (mount namespace, KernelSU, Magisk socket, Zygisk,
  overlayfs, errno deviation). `EXIT_ON_CRITICAL` still needs a score of 70, which takes at least two
  root signals, one of them strong.
- **Emulator, automation, unofficial store.** No default signal reaches HIGH on its own, so **these
  types never terminate with the default weights.** They are still reported. If you need them to
  terminate, raise a signal's weight or confidence with `detectionTuning` so that it reaches HIGH
  alone, and accept the false-positive risk that comes with it.
- **ADB.** The ADB signal is informational and never terminates.

## Leaving a threat type out

Use `terminateOn` to keep reporting a type without ever terminating for it. Apps whose users may run
rooted or custom-ROM devices for legitimate reasons can exclude privileged access:

```kotlin
val config = MobShieldConfig.builder()
    .detectOnly(false)
    .terminationPolicy(TerminationPolicy.EXIT_ON_CRITICAL)
    .terminateOn(ThreatType.entries.toSet() - ThreatType.PRIVILEGED_ACCESS)
    .build()
```

## Termination is not a security boundary

Termination is a single call, `android.os.Process.killProcess`. Anyone able to hook the app, which is
exactly what Frida and Xposed do, can replace that call with a no-op, or suppress the checks that
would have triggered it. Termination therefore raises the cost of casual tampering; it does not stop a
determined attacker, and it should not be the only thing between an attacker and something valuable.

Make decisions that matter on your server. Everything the client sends, including MobShield's
reports, can be altered by the same attacker who can hook the app, so base those decisions on
platform attestation (the [Play Integrity API](https://developer.android.com/google/play/integrity))
and use MobShield's reports as additional context.

## Choosing a policy

1. Ship in detect-only mode first and look at what your real users' devices report.
2. If you then want termination, prefer `EXIT_ON_CRITICAL`, and limit `terminateOn` to the types
   whose false positives you can accept.
3. Use `EXIT_ON_BYPASS` only if locking out some legitimate users is acceptable for your app. It acts
   on HIGH events, which the corroboration rule makes safer but which still rest on uncalibrated
   weights.

## Changes in this version

- Termination requires a signal that reaches HIGH on its own (corroboration). Weak hints that only
  add up to HIGH or CRITICAL no longer end the process.
- New `terminateOn` option, defaulting to every threat type.
- With the default weights, emulator, automation and unofficial-store events no longer terminate.
