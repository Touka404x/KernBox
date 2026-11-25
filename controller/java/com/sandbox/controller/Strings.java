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
                ? "请确认已刷入 KernBox 模块并授权本控制端签名"
                : "Ensure the KernBox module is active and authorized";
    }

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
            return (zh ? "User " : "User ") + userId + " · " + procs + (zh ? " 个活跃进程 · " : " procs · ") + variant;
        }
        return "User " + userId + " · " + procs + (zh ? " 个活跃进程" : " active procs");
    }
}
