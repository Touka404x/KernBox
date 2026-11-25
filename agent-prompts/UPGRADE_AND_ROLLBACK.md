# 无感升级与应急回滚提示词（UPGRADE_AND_ROLLBACK）

包含两个常用场景：
1. **升级 / 跨变体迁移**（带 `upgrade_fence` 防漏流围栏）
2. **应急停用与彻底回滚**（含开机卡顿/熔断恢复）

---

## 场景 A：升级或切换新变体（发给电脑 Agent）

```text
请帮我将手机上的 KernBox 升级（或迁移）到目标新版本/新变体 ZIP，保持工作资料用户不丢失并保留现有 `stealth.json` / `perf.json` 配置。

1. 先按 `./tools/probe_device.ps1`（或 `.sh`）和 `./tools/select_variant.py` 重新确认目标 ZIP `<artifact>` 与当前手机 100% 匹配，并校验 SHA-256。
2. 在电脑侧拉取一份当前配置备份：`adb shell su -c "cat /data/adb/sandbox_guard/stealth.json"`（仅保存在本机隔离临时备份目录，不展示敏感内容）和 `perf.json`、`policy.json`。
3. 触发升级围栏（如果存在外部代理核升级窗口）并停止旧守护服务：
   - 如仅升级代理核：`adb shell su -c "/data/adb/sandbox_guard/sandbox_guard ctl upgrade-begin 90"` -> 升级外部代理 -> `ctl upgrade-end`。
   - 升级本模块 ZIP：按当前 Root 管理器刷入：
     - KSU: `ksud module install /data/local/tmp/<artifact>`
     - Magisk: `magisk --install-module /data/local/tmp/<artifact>`
     - APatch: `apd module install /data/local/tmp/<artifact>`
4. **征求我确认后**运行 `adb reboot`。
5. 开机后运行 `ctl variant-info` 与 `ctl status` 确认新版本、新变体上线且工作资料 App 正常启动。
```

---

## 场景 B：开机卡顿 / 一键紧急停用与回滚

如果发生意外问题（模块默认带有**两次连续开机未完成自动生成 `zygisk_disabled` 熔断**机制）：

```text
请帮我紧急停用或回滚 KernBox，恢复工作资料常规放行：

### 方案 1：仅关闭 Zygisk 隐身钩子（保留守护进程与网络隔离）
adb shell su -c "/data/adb/sandbox_guard/sandbox_guard ctl stealth-toggle off"
# 若需彻底禁用 Zygisk 组件重启生效：
adb shell su -c "touch /data/adb/modules/sandbox_guard/zygisk_disabled && chmod 0644 /data/adb/modules/sandbox_guard/zygisk_disabled"

### 方案 2：彻底停用整个 Root 模块（不清用户应用数据）
adb shell su -c "sh /data/adb/modules/sandbox_guard/service.sh stop || true"
adb shell su -c "touch /data/adb/modules/sandbox_guard/disable"
# 征求确认后执行：adb reboot

### 方案 3：Recovery / 安全模式卸载
1. 长按电源键进入物理按键安全模式（KernelSU / Magisk / APatch 均支持音量键安全模式自动禁用全部模块）。
2. 或在 TWRP / ADB Root 下移除模块并清理运行状态：
   `rm -rf /data/adb/modules/sandbox_guard /data/adb/modules_update/sandbox_guard`
   （如需保留配置可保留 `/data/adb/sandbox_guard/*.json`，否则一并删除）。
```
