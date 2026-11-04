# MobShield and OWASP MASVS

This page maps what MobShield Android detects to the resilience controls of the
[OWASP Mobile Application Security Verification Standard (MASVS) v2](https://mas.owasp.org/MASVS/),
group **MASVS-RESILIENCE**.

MobShield is a runtime detection library. It supplies *evidence* for these controls; it does not by
itself make an app compliant, and MASVS-RESILIENCE is defense in depth rather than a guarantee. See
[When to use it](../README.md#when-to-use-it-and-when-not-to).

| MASVS control | Intent | MobShield module | Signals (see [detection notes](detection)) |
|---------------|--------|------------------|--------------------------------------------|
| MASVS-RESILIENCE-1 | The app validates the integrity of the platform | `mobshield-detect-root`, `mobshield-detect-environment` | Root: `android.root.*` (mount namespace, Magisk UDS, overlayfs, Zygisk maps, KernelSU). Environment: `android.env.*` (QEMU properties and devices, Goldfish CPU, build fingerprint, sensor count) |
| MASVS-RESILIENCE-2 | The app implements anti-tampering mechanisms | `mobshield-detect-integrity` | `android.integrity.signature`, `android.integrity.apk_checksum`, `android.integrity.native_lib_checksum`, `android.store.installer` |
| MASVS-RESILIENCE-4 | The app implements anti-dynamic analysis techniques | `mobshield-detect-hooks`, `mobshield-detect-debugger`, `mobshield-detect-environment` | Hooks: `common.hook.*`, `android.hook.*` (Frida maps, port, threads, Xposed and LSPosed). Debugger: `android.debug.*` (TracerPid, ptrace, timing, debuggable flag, waiting for debugger). Automation: `android.automation.framework` |

## Not covered

- **MASVS-RESILIENCE-3** (anti-static analysis: obfuscation and similar). Use your build toolchain
  (R8/ProGuard and dedicated obfuscators). MobShield does not obfuscate your code.
- **MASVS-RESILIENCE-1 beyond the signals above.** There is no device attestation in this
  library. Combine it with a server-verified attestation service for that.

## Using the mapping

Each signal's name, technique, default weight and confidence are listed in the per-module pages
under [docs/detection](detection). The [validation matrix](validation.md) shows what each
module reports on a clean device versus a compromised one, which is the evidence to cite when
documenting a control.
