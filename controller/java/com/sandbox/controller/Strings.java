package com.sandbox.controller;

import java.util.Locale;

/**
 * Bilingual UI strings (ZH / EN) selected cleanly from device locale.
 */
public final class Strings {

    private final boolean zh;

    public Strings() {
        String lang = Locale.getDefault().getLanguage();
        this.zh = lang != null && lang.toLowerCase(Locale.ROOT).startsWith("zh");
    }

    public String brandTitle() { return "KernBox"; }
    public String modeOffline() { return zh ? "未连接" : "Offline"; }
    public String modeStandby() { return zh ? "待机" : "Standby"; }
    public String modeTProxy() { return "TProxy"; }
    public String modeIsolated() { return zh ? "运行中" : "Isolated"; }

    public String statusActiveTitle() { return zh ? "沙盒运行中" : "Sandbox Active"; }
    public String statusPausedTitle() { return zh ? "沙盒已暂停" : "Sandbox Paused"; }
    public String statusOfflineTitle() { return zh ? "守护进程未连接" : "Daemon Unreachable"; }
    public String statusBusyTitle() { return zh ? "正在同步状态…" : "Syncing Sandbox…"; }

    public String offlineHint() {
        return zh
                ? "请确认已刷入 KernBox 模块并绑定下方签名指纹"
                : "Ensure the KernBox module is active and pin this signing digest";
    }
    public String offlineCertTitle() { return zh ? "本控制端 SHA-256 签名" : "Controller Cert SHA-256"; }
    public String btnCopyCert() { return zh ? "复制指纹" : "Copy Digest"; }
    public String copiedCertToast() { return zh ? "已复制 SHA-256 指纹到剪贴板" : "Copied SHA-256 digest"; }
    public String copiedPkgToast() { return zh ? "已复制包名" : "Package name copied"; }

    public String btnStart() { return zh ? "启动沙盒" : "Start Sandbox"; }
    public String btnPause() { return zh ? "暂停沙盒" : "Pause Sandbox"; }
    public String btnSyncing() { return zh ? "处理中…" : "Working…"; }
    public String btnRetry() { return zh ? "重新连接" : "Reconnect"; }

    public String metricApps() { return zh ? "沙盒应用" : "Apps"; }
    public String metricGate() { return zh ? "隔离链路" : "Isolation"; }
    public String metricFreeze() { return zh ? "休眠态" : "Freeze"; }
    public String gateOpen() { return zh ? "闭锁防护" : "Fail-Closed"; }
    public String gateLocked() { return zh ? "待就绪" : "Standby"; }
    public String freezeHot() { return zh ? "热冻结" : "Hot-Frozen"; }
    public String freezeAwake() { return zh ? "唤醒" : "Awake"; }

    public String sectionApps() { return zh ? "工作区应用" : "Workspace Apps"; }
    public String emptyTitle() { return zh ? "工作区暂无应用" : "No Apps in Sandbox"; }
    public String emptySubtitle() {
        return zh
                ? "点击右下角 + 号从主空间导入或安装 APK"
                : "Tap + below to import an app or stage an APK";
    }

    public String sheetTitle() { return zh ? "添加应用到沙盒" : "Add App to Sandbox"; }
    public String tabDeviceApps() { return zh ? "本机应用" : "Device Apps"; }
    public String tabInstallApk() { return zh ? "安装 APK" : "Install APK"; }
    public String searchHint() { return zh ? "搜索应用名称或包名…" : "Search app or package…"; }
    public String btnImport() { return zh ? "添加" : "Add"; }
    public String btnAdded() { return zh ? "已添加" : "Added"; }
    public String scanningApps() { return zh ? "正在读取本机应用…" : "Loading device apps…"; }
    public String noMatches() { return zh ? "没有可导入的匹配应用" : "No matching apps available"; }

    public String apkPathLabel() {
        return zh
                ? "请输入设备内允许目录的 APK 路径（/data/local/tmp/ 或 /data/adb/sandbox_guard/staging/）："
                : "Enter a staged APK path (/data/local/tmp/ or /data/adb/sandbox_guard/staging/):";
    }
    public String apkPathHint() { return "/data/local/tmp/app.apk"; }
    public String btnInstallApk() { return zh ? "安装到工作区" : "Install into Sandbox"; }
    public String invalidApkPath() {
        return zh
                ? "路径需为 /data/local/tmp/ 或 staging/ 下的 .apk"
                : "Path must be a clean .apk inside /data/local/tmp/ or staging/";
    }

    // Long-press app action sheet
    public String actionLaunch() { return zh ? "在沙盒中启动" : "Launch in Sandbox"; }
    public String actionStop() { return zh ? "单独强停进程" : "Force Stop in Sandbox"; }
    public String actionCopyPkg() { return zh ? "复制包名" : "Copy Package Name"; }
    public String actionRemove() { return zh ? "从工作区移出卸载" : "Remove from Workspace"; }
    public String actionRemoveConfirm() { return zh ? "再次点击确认从工作区卸载" : "Tap again to confirm removal"; }
    public String stoppedFmt(String label) { return zh ? ("已强停 " + label) : ("Stopped " + label); }
    public String removedFmt(String label) { return zh ? ("已从工作区移出 " + label) : ("Removed " + label); }

    // Diagnostics sheet
    public String diagTitle() { return zh ? "沙盒自检与环境状态" : "Sandbox Diagnostics"; }
    public String diagRunProbe() { return zh ? "立即执行链路自检" : "Run Live Probe"; }
    public String diagRunning() { return zh ? "正在实时探测…" : "Probing…"; }
    public String diagLabelGate() { return zh ? "隔离网关" : "Isolation Gate"; }
    public String diagLabelTProxy() { return zh ? "TProxy 就绪" : "TProxy Ready"; }
    public String diagLabelPreset() { return zh ? "当前区域预设" : "Active Preset"; }
    public String diagLabelStealth() { return zh ? "Zygisk 隐身" : "Zygisk Stealth"; }
    public String diagLabelDns() { return zh ? "系统私人 DNS" : "Private DNS"; }
    public String diagLabelSockets() { return zh ? "工作区卡死连接" : "Stuck Sockets"; }
    public String diagLabelVerify() { return zh ? "独立探针状态" : "Verify Probe"; }
    public String diagValOk() { return zh ? "正常" : "Ready"; }
    public String diagValWarn() { return zh ? "注意" : "Check"; }
    public String diagValDisabled() { return zh ? "已熔断关闭" : "Disabled"; }
    public String diagValEnabled() { return zh ? "已开启" : "Active"; }
    public String diagValProbePass() { return zh ? "已安装 · 探针通过" : "Installed · Passed"; }
    public String diagValProbeInstalled() { return zh ? "已安装（点击自检）" : "Installed (Tap Probe)"; }
    public String diagValProbeAbsent() { return zh ? "未安装（洁净态）" : "Not Installed (Clean)"; }

    public String launchingFmt(String label) {
        return zh ? ("正在沙盒中启动 " + label) : ("Launching " + label + " in sandbox");
    }
    public String importedFmt(String label) {
        return zh ? ("已添加 " + label + " 到工作区") : ("Added " + label + " to sandbox");
    }
    public String installedApkOk() {
        return zh ? "APK 已安装到沙盒工作区" : "APK installed into sandbox";
    }
    public String failPrefix() { return zh ? "操作失败：" : "Failed: "; }
    public String userLineFmt(int userId, int procs, String variant) {
        if (variant != null && !variant.isEmpty()) {
            return "User " + userId + " · " + procs + (zh ? " 个活跃进程 · " : " procs · ") + variant;
        }
        return "User " + userId + " · " + procs + (zh ? " 个活跃进程" : " active procs");
    }
}
