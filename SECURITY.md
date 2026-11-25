# Security Policy

## Supported Versions

| Version | Supported | Notes |
| :--- | :--- | :--- |
| `1.x` | Yes | Current KernBox open-source release line (`oss-main` / `main`) |

## Security Architecture Commitments

KernBox enforces least-privilege separation across untrusted Work Profile apps, a minimal `sandbox_broker`, root `sandbox_guard`, and Zygisk hooks:

- **Fail-Closed Network Isolation**: Netfilter rules (`SBW_RAW_OUTPUT`) block or reset Work Profile traffic before an authenticated proxy core acknowledgement arrives and during bounded `StateUpgradingFence` windows.
- **No Sensitive Data or Prebuilt Keys**: Release artifacts and repository sources contain zero telemetry endpoints, zero hardware identifiers, and zero embedded private keys or release keystores (`KernBoxVerify.apk` signs with an ephemeral key unless `--keystore` is explicitly provided).
- **Local Anonymized Probing**: [`tools/probe_device.ps1`](tools/probe_device.ps1) and [`tools/probe_device.sh`](tools/probe_device.sh) operate read-only and never collect serials, IMEIs, MAC addresses, or IP addresses.

## Reporting a Vulnerability

If you discover a sandbox escape, Netfilter leak, UDS privilege-escalation vector, SELinux over-permission, or bootloop trigger:

1. **Do NOT open a public GitHub issue** with working exploit steps or sensitive dumps.
2. Use GitHub **Private Vulnerability Reporting** (**Security -> Advisories -> Report a vulnerability**) on this repository if enabled, or contact the maintainers privately with:
   - Affected KernBox version and variant (`<oem>-<kernel>-<root>`)
   - Android version, kernel version (`uname -r`), and root manager version
   - Minimal reproduction steps and sanitized logs (never include device serials, IMEIs, MACs, private IPs, or real package lists)
3. Please allow reasonable time for triage, patch development across affected build-tag profiles, and coordinated disclosure.
