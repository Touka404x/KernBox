#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Read-only anonymized ADB device prober for KernBox multi-variant selection.
.DESCRIPTION
  Collects OEM signals, Android SDK, CPU ABI, kernel version, cgroup v2 freezer support,
  TProxy netfilter support, root manager flavor, and Zygisk provider availability.
  Compatible with Windows PowerShell 5.1+ and PowerShell 7+.
  Never collects or outputs hardware serials, IMEI, MAC addresses, or IP addresses.
#>
[CmdletBinding()]
param(
    [string]$Serial = "",
    [string]$Out = "",
    [string]$Adb = "adb"
)

$ErrorActionPreference = "Stop"

function Invoke-Adb {
    param([string[]]$AdbArgs)
    $full = @()
    if ($Serial -ne "") {
        $full += @("-s", $Serial)
    }
    $full += $AdbArgs
    $res = & $Adb @full 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "adb $($full -join ' ') failed ($LASTEXITCODE): $($res -join ' ')"
    }
    return ($res | Out-String).Trim()
}

$adbCmd = Get-Command $Adb -ErrorAction SilentlyContinue
if (-not $adbCmd -and -not (Test-Path $Adb)) {
    throw "ADB executable '$Adb' not found in PATH."
}

$devicesRaw = & $Adb devices 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "adb devices failed: $($devicesRaw -join ' ')"
}
$online = @()
foreach ($line in ($devicesRaw -split "`r?`n")) {
    if ($line -match '^(\S+)\s+device\b') {
        $online += $Matches[1]
    } elseif ($line -match '^(\S+)\s+(unauthorized|offline)\b') {
        if ($Serial -eq "" -or $Serial -eq $Matches[1]) {
            throw "ADB device is $($Matches[2]). Unlock screen and accept RSA authorization."
        }
    }
}
if ($online.Count -eq 0) {
    throw "No authorized online ADB device found."
}
if ($Serial -eq "" -and $online.Count -gt 1) {
    throw "Multiple ADB devices detected ($($online.Count)); pass -Serial <target> to disambiguate."
}

$shellProbe = @'
getprop_s() { getprop "$1" 2>/dev/null | tr -d "\r\n"; }
echo "MFG=$(getprop_s ro.product.manufacturer)"
echo "BRAND=$(getprop_s ro.product.brand)"
echo "SDK=$(getprop_s ro.build.version.sdk)"
echo "REL=$(getprop_s ro.build.version.release)"
echo "ABI=$(getprop_s ro.product.cpu.abi)"
echo "FLAVOR=$(getprop_s ro.build.flavor)"
echo "MIUI_UI=$(getprop_s ro.miui.ui.version.name)"
echo "HYPEROS=$(getprop_s ro.mi.os.version.name)"
echo "OPLUSROM=$(getprop_s ro.build.version.oplusrom)"
echo "ONEUI=$(getprop_s ro.build.version.oneui)"
echo "KREL=$(uname -r 2>/dev/null | tr -d '\r\n')"
echo "USERS_V=$(cmd user list -v 2>/dev/null | tr '\n' '|' | tr -d '\r')"
echo "USERS_PM=$(pm list users 2>/dev/null | tr '\n' '|' | tr -d '\r')"

ROOT_OUT=$(su -c '
  rmgr="none"; rver=""
  if [ -x /data/adb/ksu/bin/ksud ]; then
    rmgr="ksu"
    rver=$(/data/adb/ksu/bin/ksud -V 2>/dev/null | head -n1 || true)
  elif command -v ksud >/dev/null 2>&1; then
    rmgr="ksu"
    rver=$(ksud -V 2>/dev/null | head -n1 || true)
  elif [ -x /data/adb/ap/bin/apd ]; then
    rmgr="apatch"
    rver=$(/data/adb/ap/bin/apd -V 2>/dev/null | head -n1 || true)
  elif command -v apd >/dev/null 2>&1; then
    rmgr="apatch"
    rver=$(apd -V 2>/dev/null | head -n1 || true)
  elif command -v magisk >/dev/null 2>&1; then
    rmgr="magisk"
    rver=$(magisk -v 2>/dev/null | head -n1 || true)
  elif [ -d /data/adb/ksu ]; then
    rmgr="ksu"
  elif [ -d /data/adb/ap ]; then
    rmgr="apatch"
  elif [ -d /data/adb/magisk ]; then
    rmgr="magisk"
  fi
  zy=0
  for p in /data/adb/modules/*; do
    [ -d "$p" ] && [ ! -e "$p/disable" ] && [ ! -e "$p/remove" ] || continue
    mod_id=""
    if [ -f "$p/module.prop" ]; then
      mod_id=$(grep -m1 "^id=" "$p/module.prop" 2>/dev/null | cut -d= -f2 | tr -d "\r\n" | tr "A-Z" "a-z" || true)
    fi
    base=${p##*/}
    base_low=$(printf "%s" "$base" | tr "A-Z" "a-z")
    case "$mod_id:$base_low" in
      *zygisksu*|*rezygisk*|*zygisknext*|*zygisk_next*) zy=1 ;;
    esac
  done
  if [ "$zy" = 0 ] && [ "$rmgr" = "magisk" ]; then
    if magisk --sqlite "SELECT value FROM settings WHERE key='\''zygisk'\''" 2>/dev/null | grep -q "1"; then
      zy=1
    fi
  fi
  cg2=0
  if ls /sys/fs/cgroup/uid_*/cgroup.freeze >/dev/null 2>&1 || [ -e /sys/fs/cgroup/uid_0/cgroup.freeze ]; then
    cg2=1
  elif grep -qs "cgroup2" /proc/mounts 2>/dev/null && find /sys/fs/cgroup -maxdepth 2 -name cgroup.freeze 2>/dev/null | grep -q .; then
    cg2=1
  fi
  tp=0
  if grep -qw TPROXY /proc/net/ip_tables_targets 2>/dev/null; then
    tp=1
  elif iptables -t mangle -L PREROUTING -n >/dev/null 2>&1 && zcat /proc/config.gz 2>/dev/null | grep -Eq "CONFIG_NETFILTER_XT_TARGET_TPROXY=[ym]"; then
    tp=1
  fi
  inst=0
  [ -d /data/adb/modules/sandbox_guard ] || [ -x /data/adb/sandbox_guard/sandbox_guard ] && inst=1
  printf "ROOT=%s\nROOTVER=%s\nZYGISK=%s\nCG2=%s\nTPROXY=%s\nINSTALLED=%s\n" "$rmgr" "$rver" "$zy" "$cg2" "$tp" "$inst"
' 2>/dev/null || echo "ROOT=none")
echo "$ROOT_OUT"
'@

$raw = Invoke-Adb @("shell", $shellProbe)
$kv = @{}
foreach ($line in ($raw -split "`r?`n")) {
    $idx = $line.IndexOf('=')
    if ($idx -gt 0) {
        $k = $line.Substring(0, $idx).Trim()
        $v = $line.Substring($idx + 1).Trim()
        $kv[$k] = $v
    }
}

$krel = "$($kv['KREL'])"
$kmaj = 0
$kmin = 0
if ($krel -match '^(\d+)\.(\d+)') {
    $kmaj = [int]$Matches[1]
    $kmin = [int]$Matches[2]
}

$sdk = 0
if ("$($kv['SDK'])" -match '^\d+$') { $sdk = [int]$kv['SDK'] }

$workUserSet = New-Object 'System.Collections.Generic.SortedSet[int]'
if ($kv['USERS_V']) {
    foreach ($u in ($kv['USERS_V'] -split '\|')) {
        if ($u -match 'id=(\d+).*(MANAGED_PROFILE|profile\.MANAGED)') {
            $uid = [int]$Matches[1]
            if ($uid -gt 0 -and $uid -ne 999) { [void]$workUserSet.Add($uid) }
        }
    }
}
if ($kv['USERS_PM']) {
    foreach ($u in ($kv['USERS_PM'] -split '\|')) {
        if ($u -match 'UserInfo\{(\d+):[^:]*:([0-9a-fA-F]+)\}') {
            $uid = [int]$Matches[1]
            $flags = [Convert]::ToInt32($Matches[2], 16)
            if ($uid -gt 0 -and $uid -ne 999 -and (($flags -band 0x20) -ne 0)) {
                [void]$workUserSet.Add($uid)
            }
        }
    }
}
$workUsers = @()
foreach ($uid in $workUserSet) { $workUsers += $uid }

$rootMgr = "none"
if ($kv['ROOT'] -and $kv['ROOT'] -ne "") { $rootMgr = "$($kv['ROOT'])" }

$profile = [ordered]@{
    schema_version = 1
    manufacturer = "$($kv['MFG'])"
    brand = "$($kv['BRAND'])"
    android_sdk = $sdk
    android_release = "$($kv['REL'])"
    cpu_abi = "$($kv['ABI'])"
    kernel_release = $krel
    kernel_major = $kmaj
    kernel_minor = $kmin
    oem_signals = [ordered]@{
        miui_ui_version = "$($kv['MIUI_UI'])"
        hyperos_version = "$($kv['HYPEROS'])"
        oplusrom = "$($kv['OPLUSROM'])"
        oneui = "$($kv['ONEUI'])"
        build_flavor = "$($kv['FLAVOR'])"
    }
    root_manager = $rootMgr
    root_version = "$($kv['ROOTVER'])"
    zygisk_detected = ($kv['ZYGISK'] -eq '1')
    cgroup_v2_freeze = ($kv['CG2'] -eq '1')
    tproxy_capable = ($kv['TPROXY'] -eq '1')
    work_profile_users = @($workUsers)
    existing_guard_installed = ($kv['INSTALLED'] -eq '1')
}

$json = $profile | ConvertTo-Json -Depth 4
if ($Out -ne "") {
    if ([System.IO.Path]::IsPathRooted($Out)) {
        $resolvedOut = [System.IO.Path]::GetFullPath($Out)
    } else {
        $resolvedOut = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $Out))
    }
    $outDir = Split-Path -Parent $resolvedOut
    if ($outDir) {
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($resolvedOut, $json.Replace("`r`n", "`n") + "`n", $utf8NoBom)
    Write-Output "Wrote anonymized device profile to $resolvedOut"
} else {
    Write-Output $json
}
