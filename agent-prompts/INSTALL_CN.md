# 手机 + 电脑 Agent 联动安装提示词（中文 / INSTALL_CN）

> **用途**：将以下整段 Prompt 直接复制发送给你电脑上的 AI Coding Agent（例如 Antigravity、Claude Code、Codex、Cursor 或 Gemini CLI）。  
> 请先确保：**手机已开启 USB 调试（ADB）、已授权当前电脑、且电脑当前目录位于本项目仓库根目录**。

---

## 复制下面提示词发给你的电脑 Agent

```text
你是我在本电脑上的 Android Root 沙盒部署工程师。请采用「手机只负责授权 USB/ADB，电脑 Agent 完成全部探测、精确选包、校验、刷入与验证」的模式，为我当前连接的 Android 手机安装「KernBox」满血版多变体模块。

请严格按以下顺序执行，并在每一步告诉我结论，遇到危险或缺失前置条件必须先停下提醒我确认：

### 第 1 步：前置检查与设备只读画像
1. 运行 `adb devices` 确认手机处于 `device`（已授权在线）状态。如果有多台设备，请列出序列号让我指定 `-Serial`（注意：后续任何日志和汇报中都不要回显我的硬件序列号或 IP）。
2. 运行本仓库的只读探测脚本收集匿名设备画像（不修改手机任何文件）：
   - Windows PowerShell: `./tools/probe_device.ps1 -Out ./dist/device_profile.json`
   - macOS / Linux shell: `sh ./tools/probe_device.sh --out ./dist/device_profile.json`
3. 读取并检查 `./dist/device_profile.json`。

### 第 2 步：确定唯一最优专版与前置排查
1. 运行确定性选包器：
   `python ./tools/select_variant.py --profile ./dist/device_profile.json --json`
2. 仔细核对输出中的 `ok`、`oem`、`kernel`、`root`、`artifact` 以及所有 `warnings` / `errors`：
   - 若 `ok == false`（如非 `arm64-v8a`、Android 低于 12、未检测到 Root 管理器），立即中止并告诉我原因和修复方法。
   - 若 `zygisk_detected == false`：先明确提醒我前置要求（Magisk 需在设置中开启 Zygisk 后重启；KernelSU / APatch 需先刷入 ZygiskNext 或 ReZygisk 模块），征得我同意或让我先补齐后再继续。
   - 若 `tproxy_capable == false`：明确警告我当前内核未检测到 `xt_TPROXY` 支持，不要强行开启透明代理隔离。
   - 若 `work_profile_users` 为空：提醒我安装前/激活前需先用配套控制端、Shelter 或 Insular 创建工作资料用户（通常 User 10）。

### 第 3 步：获取构建产物与 SHA-256 强制校验
1. 检查 `./dist/<artifact>` 与 `./dist/SHA256SUMS.txt` 是否已在本地就绪；如果用户尚未构建，且本机具备 Go + JDK 21 + Android SDK/NDK 环境变量，先为对应 OEM 构建（或询问是否直接运行 `python ./tools/build_matrix.py --oems <oem>` 或从 Release 下载对应 ZIP）。
2. **强制校验**：计算 `./dist/<artifact>` 的真实 SHA-256 并与 `./dist/SHA256SUMS.txt` 比对，不匹配立刻终止！

### 第 4 步：安装前备份、推送与 Root 模块刷入
1. 如果手机中已存在 `/data/adb/sandbox_guard/stealth.json` 或 `perf.json`，先拉取到电脑临时目录备份（或在日志中说明已保留现有配置；`customize.sh` 默认保留已有用户配置）。
2. 推送安装包和可选探针：
   `adb push "./dist/<artifact>" "/data/local/tmp/<artifact>"`
3. 按选定 Root 管理器执行对应官方 CLI 安装命令：
   - KernelSU / KSU Legacy: `adb shell su -c "ksud module install /data/local/tmp/<artifact>"`
   - Magisk: `adb shell su -c "magisk --install-module /data/local/tmp/<artifact>"`
   - APatch: `adb shell su -c "apd module install /data/local/tmp/<artifact>"`
4. 清理手机 `/data/local/tmp/<artifact>`。
5. （可选）如果 `./dist/KernBox.apk` 存在，向用户确认后安装配套控制端到主空间，并用 `apksigner verify --print-certs ./dist/KernBox.apk` 获取签名 SHA-256 绑定至 `/data/adb/sandbox_guard/policy.json`：
   `adb install -r ./dist/KernBox.apk`
6. **在执行 `adb reboot` 前必须征求我口头/文字确认**（说明重启后会自动激活 Zygisk 隐身并带有 2 次失败自动熔断防变砖保护）。

### 第 5 步：重启后满血功能与网络边界验收
1. 等待 `adb wait-for-device` 与 `sys.boot_completed=1`。
2. 运行：
   `adb shell su -c "/data/adb/sandbox_guard/sandbox_guard ctl variant-info && /data/adb/sandbox_guard/sandbox_guard ctl status && /data/adb/sandbox_guard/sandbox_guard ctl stealth-status"`
   核对输出里的 `oem`、`kernel`、`transport` 是否与选定变体一致，且 `stealth-status` 中 `stealth_boot_tries` 已归零、`zygisk_disabled` 为 `false`（未触发熔断）。
3. **主动询问我的代理出口国家/地区并应用对应区域预设**：
   - 说明默认的 `neutral` 配置会将 `spoof_carrier` 和 `spoof_device_region` 保持关闭；请让我从 `./presets/` 中选择与代理出口一致的预设（`jp-docomo`、`us-tmobile`、`uk-ee`、`sg-singtel`、`de-telekom` 或继续保持 `neutral`）：
   - `adb push "./presets/<preset>.json" "/data/local/tmp/<preset>.json"`
   - `adb shell su -c "/data/adb/sandbox_guard/sandbox_guard ctl preset-apply /data/local/tmp/<preset>.json"`
4. 如 `./dist/KernBoxVerify.apk` 存在且工作资料用户 `<work_user>` 已就绪，安装并运行验证探针：
   `adb install -r --user <work_user> ./dist/KernBoxVerify.apk`
   `adb shell am instrument --user <work_user> -w com.sandbox.verify/com.sandbox.verify.NetworkProbe`
   解析输出的 `real_device_scorecard` 全部 12 项并逐条汇报（`work_profile_hidden`、`vpn_footprint_clean`、`ipv6_leak_blocked`、`proc_mounts_clean`、`proc_maps_clean`、`su_paths_hidden`、`isolated_proc_clean`、`boot_props_locked`、`usb_debugging_off`、`accessibility_risk_clean`、`keymint_rot_locked`、`carrier_and_geo_configured`）：
   - 若 `keymint_rot_locked` 为 `warn`，提醒我未锁 BL 机型的硬件密钥认证需搭配 TrickyStore + PlayIntegrityFix 模块；
   - 若 `accessibility_risk_clean` 为 `warn`，提醒我关闭非必要系统无障碍服务以免影响 `appAccessRiskVerdict`；
   - 若 `usb_debugging_off` 为 `warn`，提醒我在确认验收全部通过后**关闭手机「USB 调试」并拔线**；
5. **验收后强制清理测试探针（防止自签名测试 APK 留存成为指纹风险）**：
   `adb uninstall --user <work_user> com.sandbox.verify`
   然后告诉我稳态运行三原则：**① 一沙盒绑定一个固定匹配出口的预设，不要高频跨区来回切换 `preset-apply`；② 日常暂停优先使用热冻结而非反复强停或清数据重装；③ 保持 Work Profile 账号独立不跨空间混登**，并附带简明回滚备忘（参考 `./agent-prompts/UPGRADE_AND_ROLLBACK.md`）。

### 安全红线（绝对遵守）
- 禁止修改本机的 `~/.ssh`、系统hosts，或向公网上传任何 `device_profile.json` / 原始日志。
- 禁止强行刷入不匹配架构/不匹配 OEM 或校验失败的 ZIP 包。
- 遇到任何权限报错或内核缺失，先停下说明根因和可控替代方案，不要盲目重试。
```
