# Android Sandbox Guard — Root + 内核满血多变体工作资料隔离沙盒

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **一个真正做到「极致瘦身、一机一专版、手机 + 电脑 Agent 联动即装」的开源 Android Root 工作资料隔离与隐身系统。**

## 为什么不做成一个“大而全”的臃肿安装包？

传统多机型兼容模块往往把所有厂商逻辑、旧内核兼容、不同 Root 框架与无用分支全塞进同一个包里——带来体积膨胀、运行时无效分支判断、不必要的权限规则与隐身特征面扩大。

**Android Sandbox Guard 的设计原则恰恰相反**：
通过 **编译期裁剪 + 专用打包（30 个精简专版）**，让每一台手机只装入与自身硬件、OEM 系统、内核能力与 Root 管理器精确匹配的最小代码集合：
- **5 个 OEM 特化（Go Build Tags + C++ 编译期宏）**：`hyperos`（小米/Redmi/POCO）、`oplus`（OnePlus/OPPO/Realme）、`oneui`（三星）、`aosp`（Pixel / LineageOS / GrapheneOS）、`generic`（通用兼容）
- **2 档内核能力分级**：
  - `k510`（Linux 5.10+）：启用 `openat2(RESOLVE_BENEATH)`、`pidfd_open`/`pidfd_send_signal`、`process_madvise(MADV_PAGEOUT)` 与 cgroup v2 `cgroup.freeze` 满血内核路径
  - `k419`（Linux 4.14–5.9 / cgroup v1）：编译期切换 `-tags kernel_compat`，使用防符号链接组件逐级打开、双重 `/proc` UID+starttime 验证查杀与 cgroup v1 freezer 兼容路径
- **4 类 Root 管理器打包与 SELinux 策略模板**：`ksu`、`ksu_legacy`、`magisk`、`apatch`

> 安装包内置 **AI Agent 安装/诊断/回滚 Prompt** 与只读设备探测脚本，你只需要让手机通过 USB 连接电脑，把提示词复制给电脑上的 AI Agent，它会自动完成匿名探测、专版匹配、SHA-256 校验、刷入与验收。

---

## 核心能力（Root + 内核满血版）

1. **零内核旁路强一致透明代理防火墙（Fail-Closed Netfilter）**：
   - 基于 `iptables-restore --noflush` 原子事务管理 `SBW_RAW_OUTPUT` / `SBW_OUTPUT` / `SBW_EGRESS` / `SBW_TPROXY_OUT` / `SBW_TPROXY_PRE` 链路；
   - 默认主路径零 `TRANSPORT_VPN` 痕迹，配合多代际升级围栏（`upgrade_fence`：`StateBlockedBoot` -> `StateBlockedLocked` -> `StateAckWait` -> `StateOpen` <-> `StateUpgradingFence`）防漏流。
2. **微秒级内核热冻结与内存回收**：
   - `k510` 原生操作 cgroup v2 `cgroup.freeze` 与 PSI/压力触发 `process_madvise(MADV_PAGEOUT)`，非激活工作资料毫秒级零耗电静默；唤醒零冷启动开销。
3. **跨进程信任边界与独立 SELinux `sandbox_broker` 域**：
   - 非特权控制器与守护进程通过双层 UDS（`/dev/socket/sandbox_ctrl/ctrl.sock` <-> `/dev/socket/sandbox_priv/guard.sock`）隔离，强制校验证书 SHA-256、`SO_PEERCRED` 与共享认证令牌。
4. **双层 Zygisk + ServiceManager 隐身框架（按 OEM 裁剪属性槽位）**：
   - Native PLT Hook 零内存分配覆写时区/区域/语言/运营商系统属性并清洗 `getifaddrs`；
   - Java `InMemoryDexClassLoader` 注入 `system_server` 与 `com.android.phone` 的动态代理，对工作资料内进程屏蔽管理资料痕迹、定位/Wi-Fi 扫描、蓝牙地址及真实网口特征；
   - 内置 **两次连续开机未完成自动熔断**（`zygisk_disabled` + 自动关闭 `stealth.json` 开关）确保不因系统升级变砖。
5. **开箱即用区域预设**：内置 [`presets/`](presets/)（`neutral`、`jp-docomo`、`us-tmobile`、`uk-ee`、`sg-singtel`、`de-telekom`），支持运行期一键切换。

---

## 30 秒上手：手机 + 电脑 Agent 联动安装

1. 手机开启 **USB 调试**并连接电脑（确认 `adb devices` 显示 `device`），安装并配置好 KernelSU / Magisk / APatch（KSU/APatch 用户建议配套启用 ZygiskNext 或 ReZygisk）。
2. 打开你电脑上的 AI Agent（Antigravity / Claude Code / Codex / Cursor 等），打开本仓库目录。
3. **直接复制 [`agent-prompts/INSTALL_CN.md`](agent-prompts/INSTALL_CN.md) 中的完整提示词发给 Agent**！

Agent 会自动执行以下标准流程（每步均可人工确认）：
```text
probe_device (.ps1/.sh)  ──▶  select_variant.py  ──▶  SHA256 强校验
         │                             │                      │
         ▼                             ▼                      ▼
   只读匿名硬件/内核画像         精确命中 30 专版之一        ksud/magisk/apd 刷入
                                                              │
         SandboxVerifyProbe.apk ◀── ctl variant-info/status ◀─┘ 重启确认
```

---

## 仓库目录结构

| 目录 / 文件 | 用途 |
| :--- | :--- |
| [`guard/`](guard/) | Go 语言系统守护进程 `sandbox_guard`、隔离 `sandbox_broker`、OEM/内核特化内部包与 `-race` 单元测试 |
| [`stealth/`](stealth/) | C++17 Zygisk PLT 模块 + Java Binder 动态代理、`stealth/build.py` 与宿主机测试 |
| [`packaging/`](packaging/) | 4 类 Root 管理器 SELinux 策略、启动脚本模板与严格 LF 检查的 `pack_variant.py` |
| [`presets/`](presets/) | 可动态热切换的区域/运营商伪装预设 JSON（支持 `ctl preset-apply`） |
| [`verify/`](verify/) | 纯 Java 独立验收探针 APK（`com.sandbox.verify`）与环境变量驱动构建脚本 |
| [`tools/`](tools/) | 匿名设备探测器、确定性选包器、全 30 变体构建器、开源隐私泄漏门禁扫描器与单元测试 |
| [`agent-prompts/`](agent-prompts/) | 面向中文/英文用户的可复制 Agent 提示词（安装、诊断、升级与应急回滚） |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | 架构原理、信任边界、状态机与多变体裁剪技术细节 |
| [`VARIANT_MATRIX.md`](VARIANT_MATRIX.md) | 全 30 个发布包映射表与编译 Flag 说明 |

---

## 开发者从源码一键构建全部 30 个专版

配置标准环境变量（`GOROOT`、`JAVA_HOME`、`ANDROID_SDK_ROOT`、`ANDROID_NDK_HOME`）后运行：

```powershell
# Windows PowerShell
.\tools\build_matrix.ps1 -Version 3.0.0-oss

# 或跨平台 Python 入口
python ./tools/build_matrix.py --version 3.0.0-oss
```

构建产物位于 `./dist/`（已加入 `.gitignore`），包含 30 个 `SandboxGuard-<oem>-<kernel>-<root>-arm64.zip`、`SandboxVerifyProbe.apk`、`SHA256SUMS.txt` 与 `variants-manifest.json`。

---

## 开源许可与合规声明

- 本项目采用 [Apache License 2.0](LICENSE) 开源协议。
- 本项目仅提供 Android 工作资料隔离、隐私安全研究与合法系统防指纹能力，严禁用于任何违法违规用途。
- **不收集、不内置、也不提交**任何真实硬件序列号、私钥证书或个人网络配置，参见 [`tools/verify_privacy_leak.py`](tools/verify_privacy_leak.py) 与 [`CONTRIBUTING.md`](CONTRIBUTING.md)。
