# Read-Only Diagnostic & Redacted Log Collection Prompt (DIAGNOSE_EN)

When `KernBox` is installed and you experience blocked traffic, app crashes, inactive Zygisk stealth, or broken proxy handshakes, send this prompt to your PC Agent for read-only, redacted root-cause analysis.

```text
Perform a read-only, redacted diagnosis of KernBox running on my connected Android phone. Never echo hardware serials, IMEIs, MAC addresses, private IPs, or personal app lists (use redacted placeholders if a package name must be referenced).

Check the following in order, then diagnose the root cause and provide minimal remediation steps:
1. Device & Variant Match:
   - Run `adb shell su -c "/data/adb/sandbox_guard/sandbox_guard ctl variant-info"`
   - Check kernel release `adb shell uname -r`, cgroup v2 `/sys/fs/cgroup/uid_*/cgroup.freeze`, and TProxy target `grep -w TPROXY /proc/net/ip_tables_targets`.
2. Daemon, Broker & External Proxy Core:
   - Run `adb shell su -c "/data/adb/sandbox_guard/sandbox_guard ctl status"`
   - Inspect `/data/adb/sandbox_guard/service.status`, `/data/adb/sandbox_guard/boot.status`, and the last 50 lines of `guard-svc.log` / `service-sup.log`.
   - Check `/data/adb/modules/sandbox_guard/zygisk_disabled` and `/data/adb/sandbox_guard/stealth_boot_tries` to see if the 2-strike bootloop kill-switch fired.
3. TProxy & Leak-Prevention Netfilter State:
   - Run `adb shell su -c "iptables -t mangle -S | grep SBW_ || true"`
   - Run `adb shell su -c "ip rule show"`
4. SELinux Broker & Unix Domain Sockets:
   - Run `adb shell su -c "ls -lZ /dev/socket/sandbox_ctrl /dev/socket/sandbox_priv /data/adb/sandbox_guard/sandbox_broker"`
   - Run `adb shell su -c "dmesg | grep -E 'sandbox_broker|sandbox_ctrl|sandbox_priv|avc: denied' | tail -n 30 || true"`
5. Lightweight Verification Probe (if `com.sandbox.verify` is installed in Work Profile `<work_user>`):
   - Run `adb shell am instrument --user <work_user> -w -e compact true com.sandbox.verify/com.sandbox.verify.NetworkProbe`

Identify whether the fault falls into:
[A] Wrong variant / kernel tier | [B] Zygisk missing or kill-switched | [C] External proxy (`sandbox_proxy`) not ready | [D] SELinux / Root manager policy denial | [E] Work Profile netfilter rules blocking traffic, and outline safe recovery steps.
```
