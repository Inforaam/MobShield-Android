# Security Policy

## Supported versions

The latest tagged release is supported. Security fixes are made on `main` and released as a new tag.

| Version | Supported          |
| ------- | ------------------ |
| Latest release (see [Releases](https://github.com/Inforaam/MobShield-Android/releases)) | :white_check_mark: |
| Older releases | :x: |

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Use GitHub's private reporting: go to the repository's **Security** tab and choose
[**Report a vulnerability**](https://github.com/Inforaam/MobShield-Android/security/advisories/new).

Include:

- Affected module (for example `mobshield-detect-root`, `mobshield-core`)
- Steps to reproduce
- Impact assessment (bypass, crash, privacy)

We aim to acknowledge reports within 72 hours and provide a remediation timeline
within 14 days for confirmed issues.

A detection bypass (a technique that defeats a signal on a device an attacker controls) is
expected to exist for any client-side detector. Reports of one are still welcome, particularly
with a reproduction, so the detector can be improved.

## Safe harbor

Good-faith security research on your own builds of the sample apps is welcome.
Do not test third-party production apps without permission.
