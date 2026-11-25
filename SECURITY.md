# Security Policy

## Supported Versions

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `1.x` | Yes | Current KernBox open-source release line (`oss-main` / `main`) |

## Security Architecture Commitments

KernBox enforces least-privilege separation across untrusted Work Profile apps, a minimal `sandbox_broker`, root `sandbox_guard`, and Zygisk hooks:

- **Fail-Closed Network Isolation**: Netfilter rules (`SBW_RAW_OUTPUT`) block or reset Work Profile traffic before an authenticated proxy core acknowledgement arrives and during bounded `StateUpgradingFence` windows.
- **No Sensitive Data or Prebuilt Keys**: Release artifacts and repository sources contain zero telemetry endpoints, zero hardware identifiers, and zero embedded private keys or release keystores (`KernBox.apk` and `KernBoxVerify.apk` sign with ephemeral keys unless `--keystore` is explicitly provided).
- **Local Anonymized Probing**: [`tools/probe_device.ps1`](tools/probe_device.ps1) and [`tools/probe_device.sh`](tools/probe_device.sh) operate read-only and never collect serials, IMEIs, MAC addresses, IP addresses, or Accessibility package names (emitting booleans only).
- **Non-Goals & Honest Threat Model**: KernBox focuses on clean Work Profile isolation, fail-closed Netfilter enforcement, process hygiene (`isolatedProcess` included), and consistent system/locale/carrier semantics. It intentionally avoids fabricating contradictory hardware identifiers (IMEI/chipset/model spoofing), does not bundle third-party TEE attestation hacks (pairing with TrickyStore/PIF is surfaced transparently when BL is unlocked), and never claims to bypass server-side rate limits, Device Recall, or account eligibility checks.

## Reporting a Vulnerability

If you discover a sandbox escape, Netfilter leak, UDS privilege-escalation vector, SELinux over-permission, or bootloop trigger:

1. **Do NOT open a public GitHub issue** with working exploit steps or sensitive dumps.
2. Use GitHub **Private Vulnerability Reporting** (**Security -> Advisories -> Report a vulnerability**) on this repository if enabled, or contact the maintainers privately with:
   - Affected KernBox version and variant (`<oem>-<kernel>-<root>`)
   - Android version, kernel version (`uname -r`), and root manager version
   - Minimal reproduction steps and sanitized logs (never include device serials, IMEIs, MACs, private IPs, or real package lists)
3. Please allow reasonable time for triage, patch development across affected build-tag profiles, and coordinated disclosure.
