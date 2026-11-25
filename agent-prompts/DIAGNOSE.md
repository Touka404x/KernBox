# 故障诊断与日志脱敏收集提示词（DIAGNOSE）

当你已安装 `KernBox` 但出现网络阻断、App 闪退、Zygisk 未生效、或升级后无法连通代理时，把下面这段发给你的电脑 Agent，让它自动采集脱敏状态并定位根因。

```text
请以只读、脱敏的方式诊断我当前手机上运行的 KernBox。全程禁止回显硬件序列号、IP 地址、MAC 地址或隐私包名列表（如必须提及自定义端，仅保留脱敏占位符）。

请依次检查以下项目并给出根因分析与精确修复建议：
1. 检查设备与变体匹配度：
   - 运行 `adb shell su -c "/data/adb/sandbox_guard/sandbox_guard ctl variant-info"`
   - 核对内核版本 `adb shell uname -r`、cgroup v2 `/sys/fs/cgroup/uid_*/cgroup.freeze`、TProxy 目标 `grep -w TPROXY /proc/net/ip_tables_targets`。
2. 检查守护进程、Broker 与外部代理核：
   - `adb shell su -c "/data/adb/sandbox_guard/sandbox_guard ctl status"`
   - 检查 `/data/adb/sandbox_guard/service.status`、`/data/adb/sandbox_guard/boot.status`、以及 `guard-svc.log` / `service-sup.log` 的最后 50 行。
   - 检查 `/data/adb/modules/sandbox_guard/zygisk_disabled` 与 `/data/adb/sandbox_guard/stealth_boot_tries`（判断是否触发了重启熔断）。
3. 检查透明代理与防泄漏链状态：
   - `adb shell su -c "iptables -t mangle -S | grep SBW_ || true"`
   - `adb shell su -c "ip rule show"`
4. 检查 SELinux Broker 与 UDS 套接字（排查 IPC / 权限问题）：
   - `adb shell su -c "ls -lZ /dev/socket/sandbox_ctrl /dev/socket/sandbox_priv /data/adb/sandbox_guard/sandbox_broker"`
   - `adb shell su -c "dmesg | grep -E 'sandbox_broker|sandbox_ctrl|sandbox_priv|avc: denied' | tail -n 30 || true"`
5. 如 Work Profile 内已安装 `com.sandbox.verify`，运行一次轻量探针检查：
   - `adb shell am instrument --user 10 -w -e mode network_fast com.sandbox.verify/com.sandbox.verify.NetworkProbe`

根据以上输出，明确告诉我故障发生在：
[A] 选错变体 / 内核不兼容 | [B] Zygisk 未开启或被熔断 | [C] 外部代理核 (`sandbox_proxy`) 未就绪 | [D] SELinux / Root 管理器策略拦截 | [E] 工作资料网络规则阻断，并给出安全恢复步骤。
```
