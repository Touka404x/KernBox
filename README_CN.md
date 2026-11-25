<p align="center">
  <img src="assets/kernbox-icon.png" width="128" height="128" alt="KernBox" />
</p>

# KernBox

**面向 Root 安卓设备的内核级零漏流隔离沙盒（专为性能拆分 30 个精简专版 · 支持手机 + 电脑 AI Agent 一键联动安装）**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Android](https://img.shields.io/badge/Android-12%2B%20ARM64-3DDC84.svg)](VARIANT_MATRIX.md)
[![Variants](https://img.shields.io/badge/Builds-30%20Lean%20Variants-0A66C2.svg)](VARIANT_MATRIX.md)
[![Root](https://img.shields.io/badge/Root-KernelSU%20%7C%20Magisk%20%7C%20APatch-black.svg)](VARIANT_MATRIX.md)

[English](README.md) · **简体中文** · [30 变体选型表](VARIANT_MATRIX.md) · [架构设计](ARCHITECTURE.md) · [AI 安装剧本](agent-prompts/INSTALL_CN.md) · [安全声明](SECURITY.md)

---

## 为什么做 KernBox？

传统的安卓工作空间 / 多机型兼容模块，往往把所有厂商逻辑、老内核回退和不同 Root 框架的判断全塞进一个大包里——结果就是安装包越来越大、运行时充满无效分支、权限规则过宽，不仅费电，还更容易留下特征。

**KernBox 反其道而行之：**
- **绝不做臃肿全家桶**：在编译阶段就按「手机系统 × 内核档位 × Root 管理器」精准拆分成 **30 个专机专用精简包**（单包仅 ~4.1 MB）。你的手机只编译和运行属于它自己的那套内核与厂商路径，把性能和隐身干净度压到极致。
- **把繁琐的选包与刷机交给电脑 AI Agent**：你不用懂内核版本号、cgroup 或 Netfilter 链路。手机插上电脑开启 USB 调试，把仓库里的提示词发给电脑上的 AI Agent，它会自动给手机体检、挑出 30 个包里最匹配的那 1 个、核对 SHA-256 哈希，并在你确认后刷入与验收。

---

## 30 秒上手：手机 + 电脑 AI Agent 联动安装（推荐）

### 准备工作
1. 一台已 Root 的 **ARM64（`arm64-v8a`）安卓 12+（API 31+）** 手机（`KernelSU`、`Magisk` 或 `APatch`），开启 **USB 调试（ADB）** 并授权连接电脑。
2. 电脑上任意支持终端操作的 AI Agent（Antigravity、Claude Code、Codex、Cursor、Gemini CLI 等）。

### 直接复制下面这段发给你的 AI Agent
在电脑上打开本仓库目录后，发送：

```text
请阅读 agent-prompts/INSTALL_CN.md，严格按其中顺序为我当前连接的安卓手机执行安装：先运行只读匿名探测脚本与 tools/select_variant.py 匹配唯一最优的 KernBox 变体包，核对 SHA256SUMS.txt 校验和，刷入模块、重启前与安装探针前都先停下来让我确认。全程禁止回显我的硬件序列号、IMEI、MAC 或 IP。
```

AI 会按标准流水线自动协助完成（每步均有安全闸门）：
```text
probe_device (.ps1/.sh)  ──▶  select_variant.py  ──▶  SHA-256 强校验
         │                             │                      │
         ▼                             ▼                      ▼
   只读匿名硬件/内核画像         精确命中 30 专版之一        ksud/magisk/apd 刷入
                                                              │
         KernBoxVerify.apk ◀── ctl variant-info/status ◀─────┘ 重启确认
```

---

## 适配哪些手机？（30 变体覆盖矩阵）

KernBox 每次发布同步产出 `5 大系统阵营 × 2 档内核能力 × 3 类 Root 管理器 = 30 个 ARM64 模块包`（`KernBox-<oem>-<kernel>-<root>-arm64.zip`）以及非特权验收探针（`KernBoxVerify.apk`）：

| 维度 | 覆盖范围 | 特化裁剪说明 |
| :--- | :--- | :--- |
| **手机系统（5 大阵营）** | `hyperos`（小米/Redmi/POCO）、`aosp`（Pixel/LineageOS/类原生）、`oplus`（一加/OPPO/realme）、`oneui`（三星）、`generic`（其他品牌兜底） | 编译期 Go `-tags oem_<oem>` 与 C++ `-DOEM_<OEM>` 精准裁剪隐藏应用逻辑、克隆用户排除、冻结适配与属性槽位；小米硬件刷类原生 ROM 也会自动命中 `aosp`。 |
| **内核档位（2 档）** | `k510`（Linux 5.10+ 且支持 cgroup v2 freeze）、`k419`（Linux 4.14–5.9 或无 cgroup v2） | `k510` 启用 `openat2`、`pidfd`、`process_madvise(MADV_PAGEOUT)` 与 cgroup v2 热冻结；`k419`（`-tags kernel_compat`）切换安全路径防符号链接与 cgroup v1 兼容路径。 |
| **Root 管理器（全覆盖）** | `ksu`、`ksu_legacy`（KSU `< 0.9` / `k419`）、`magisk`、`apatch` | 内置各管理器专用 SELinux 规则、工具链路径检索与官方 CLI 安装对接。 |

> 全部 30 个包名与编译标志明细见 [`VARIANT_MATRIX.md`](VARIANT_MATRIX.md)。

---

## 核心能力（Root + 内核满血版）

- **零漏流原子防火墙与升级围栏（Fail-Closed）**：基于 `iptables-restore --noflush` 原子事务管理 `SBW_RAW_OUTPUT`、`SBW_OUTPUT`、`SBW_EGRESS`、`SBW_TPROXY_*` 链路，启动阶段、锁态与外部代理核升级窗口自动闭锁防漏流，默认主路径零 VPN 特征。
- **微秒级热冻结与主动内存回收**：`k510` 原生操控 `cgroup.freeze` 与压力触发 `process_madvise(MADV_PAGEOUT)`，工作资料不用时几乎零后台耗电、切回即用；`k419` 自动回退 cgroup v1 / 安全休眠。
- **独立 SELinux `sandbox_broker` 权限隔离**：双层 UDS（`ctrl.sock` 与 `guard.sock`）分离控制端与 Root 守护进程，强制校验 `SO_PEERCRED`、APK 签名证书 SHA-256 与共享令牌。
- **双层 Zygisk + Binder 隐身与防卡开机熔断**：Native PLT 零内存分配覆写时区/语言/运营商属性与网口信息，配合内存加载 DEX 动态代理（`system_server` + `com.android.phone`）；内置 [`presets/`](presets/) 6 套区域模板（默认中性 `neutral`，含 `jp-docomo`、`us-tmobile`、`uk-ee`、`sg-singtel`、`de-telekom`）及 **两次连续开机未完成自动关闭隐身钩子** 保护。
- **极简伴侣控制端与独立验证探针**：随包产出纯 SDK 构建的 [`KernBox.apk`](controller/)（`com.sandbox.controller`，支持一键启停沙盒、工作区应用启动及 `+` 号导入应用 / 安装 APK）与非特权验收探针 [`KernBoxVerify.apk`](verify/)。

---

## AI 运维与救砖剧本

- 安装与首次完整验收：[`agent-prompts/INSTALL_CN.md`](agent-prompts/INSTALL_CN.md) · [English](agent-prompts/INSTALL_EN.md)
- 只读脱敏故障诊断：[`agent-prompts/DIAGNOSE.md`](agent-prompts/DIAGNOSE.md)
- 无感升级与应急回滚：[`agent-prompts/UPGRADE_AND_ROLLBACK.md`](agent-prompts/UPGRADE_AND_ROLLBACK.md)

---

## 仓库结构速览

| 目录 / 文件 | 用途 |
| :--- | :--- |
| [`guard/`](guard/) | Go 守护进程 `sandbox_guard`、`sandbox_broker`、OEM/内核特化实现与 `-race` 单元测试 |
| [`stealth/`](stealth/) | C++17 Zygisk PLT 模块 + Java Binder 动态代理与宿主机测试 |
| [`packaging/`](packaging/) | 4 类 Root 管理器 `sepolicy.rule`、启动模板与严格 LF 校验打包器 |
| [`presets/`](presets/) | 6 套区域/运营商运行期热切换预设 JSON（`ctl preset-apply`） |
| [`controller/`](controller/) | 极简伴侣控制端 APK 源码与构建脚本（`com.sandbox.controller` / `KernBox.apk`） |
| [`verify/`](verify/) | 独立验收探针 APK 源码与构建脚本（`com.sandbox.verify` / `KernBoxVerify.apk`） |
| [`tools/`](tools/) | 匿名探测脚本、确定性选包器、全 30 变体构建器、隐私泄漏门禁与单元测试 |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | 架构原理、信任边界与状态机详述 |

---

## 开发者从源码一键构建全 30 专版

配置标准环境变量（`GOROOT` / `go`、`JAVA_HOME` (JDK 21)、`ANDROID_SDK_ROOT`、`ANDROID_NDK_HOME`、Python 3.10+）后运行：

```bash
# 跨平台 Python 入口
python ./tools/build_matrix.py --version 1.0.0
```

```powershell
# Windows PowerShell 封装
.\tools\build_matrix.ps1 -Version 1.0.0
```

所有产出生成在 `./dist/`（已忽略）：30 个 `KernBox-<oem>-<kernel>-<root>-arm64.zip`、`KernBox.apk`、`KernBoxVerify.apk`、`SHA256SUMS.txt` 与 `variants-manifest.json`。源码还保留可选编译标志 `-tags transport_vpn` 供特殊兼容构建（默认公开矩阵为纯 TProxy 精简路径）。

---

## 隐私、安全与开源协议

- **隐私零采集 / 零泄漏门禁**：本地探测脚本不收集硬件序列号、IMEI、MAC 或 IP，仓库每次变更均由 [`tools/verify_privacy_leak.py`](tools/verify_privacy_leak.py) 强制拦截个人敏感信息。
- **安全与贡献**：漏洞披露见 [`SECURITY.md`](SECURITY.md)，开发与提交流程见 [`CONTRIBUTING.md`](CONTRIBUTING.md)。
- **合规声明**：本项目仅用于个人隐私保护、管理工作空间隔离与合规安全研究，使用者须遵守所在地法律法规与相关平台条款。
- **开源协议**：[Apache License 2.0](LICENSE)
