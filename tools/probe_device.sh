#!/usr/bin/env sh
# Read-only anonymized ADB device prober for KernBox variant selection.
# Collects NO hardware serials, IMEIs, MAC addresses, or IP addresses.
set -eu

SERIAL=""
OUT=""
ADB_BIN=${ADB_BIN:-adb}

while [ $# -gt 0 ]; do
    case "$1" in
        -s|--serial) SERIAL="$2"; shift 2 ;;
        -o|--out) OUT="$2"; shift 2 ;;
        --adb) ADB_BIN="$2"; shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

command -v "$ADB_BIN" >/dev/null 2>&1 || { echo "adb not found" >&2; exit 1; }

adb_run() {
    if [ -n "$SERIAL" ]; then
        "$ADB_BIN" -s "$SERIAL" "$@"
    else
        "$ADB_BIN" "$@"
    fi
}

if [ -z "$SERIAL" ]; then
    DEV_LINES=$("$ADB_BIN" devices | awk 'NR>1 && $2=="device" {print $1}')
    CNT=$(printf '%s\n' "$DEV_LINES" | sed '/^$/d' | wc -l)
    if [ "$CNT" -eq 0 ]; then
        echo "No authorized online ADB device found." >&2
        exit 1
    elif [ "$CNT" -gt 1 ]; then
        echo "Multiple ADB devices connected; pass --serial <id>." >&2
        exit 1
    fi
fi

RAW=$(adb_run shell '
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
echo "KREL=$(uname -r 2>/dev/null | tr -d "\r\n")"
echo "VBSTATE=$(getprop_s ro.boot.verifiedbootstate)"
echo "FLOCKED=$(getprop_s ro.boot.flash.locked)"
echo "BTAGS=$(getprop_s ro.build.tags)"
echo "ADB_EN=$(settings get global adb_enabled 2>/dev/null | tr -d "\r\n")"
ACC_RAW=$(settings get secure enabled_accessibility_services 2>/dev/null | tr -d "\r\n")
if [ -n "$ACC_RAW" ] && [ "$ACC_RAW" != "null" ]; then echo "ACC_ON=1"; else echo "ACC_ON=0"; fi
echo "USERS_V=$(cmd user list -v 2>/dev/null | tr "\n" "|" | tr -d "\r")"
echo "USERS_PM=$(pm list users 2>/dev/null | tr "\n" "|" | tr -d "\r")"
su -c "
  rmgr=none; rver=
  if [ -x /data/adb/ksu/bin/ksud ]; then
    rmgr=ksu
    rver=\$(/data/adb/ksu/bin/ksud -V 2>/dev/null | head -n1 || true)
  elif command -v ksud >/dev/null 2>&1; then
    rmgr=ksu
    rver=\$(ksud -V 2>/dev/null | head -n1 || true)
  elif [ -x /data/adb/ap/bin/apd ]; then
    rmgr=apatch
    rver=\$(/data/adb/ap/bin/apd -V 2>/dev/null | head -n1 || true)
  elif command -v apd >/dev/null 2>&1; then
    rmgr=apatch
    rver=\$(apd -V 2>/dev/null | head -n1 || true)
  elif command -v magisk >/dev/null 2>&1; then
    rmgr=magisk
    rver=\$(magisk -v 2>/dev/null | head -n1 || true)
  elif [ -d /data/adb/ksu ]; then
    rmgr=ksu
  elif [ -d /data/adb/ap ]; then
    rmgr=apatch
  elif [ -d /data/adb/magisk ]; then
    rmgr=magisk
  fi
  zy=0; ts=0; pif=0; hider=0
  for p in /data/adb/modules/*; do
    [ -d \"\$p\" ] && [ ! -e \"\$p/disable\" ] && [ ! -e \"\$p/remove\" ] || continue
    mod_id=
    if [ -f \"\$p/module.prop\" ]; then
      mod_id=\$(grep -m1 \"^id=\" \"\$p/module.prop\" 2>/dev/null | cut -d= -f2 | tr -d \"\r\n\" | tr \"A-Z\" \"a-z\" || true)
    fi
    base=\${p##*/}
    base_low=\$(printf \"%s\" \"\$base\" | tr \"A-Z\" \"a-z\")
    case \"\$mod_id:\$base_low\" in
      *zygisksu*|*rezygisk*|*zygisknext*|*zygisk_next*) zy=1 ;;
    esac
    case \"\$mod_id:\$base_low\" in
      *tricky_store*|*trickystore*) ts=1 ;;
    esac
    case \"\$mod_id:\$base_low\" in
      *playintegrityfix*|*playintegrity*|*pif*|*playcurl*) pif=1 ;;
    esac
    case \"\$mod_id:\$base_low\" in
      *shamiko*|*zygisk_assistant*|*susfs*) hider=1 ;;
    esac
  done
  if [ \"\$zy\" = 0 ] && [ \"\$rmgr\" = magisk ]; then
    magisk --sqlite \"SELECT value FROM settings WHERE key='\''zygisk'\''\" 2>/dev/null | grep -q 1 && zy=1
  fi
  if [ \"\$rmgr\" = ksu ] || [ \"\$rmgr\" = apatch ]; then
    hider=1
  fi
  cg2=0
  if ls /sys/fs/cgroup/uid_*/cgroup.freeze >/dev/null 2>&1 || [ -e /sys/fs/cgroup/uid_0/cgroup.freeze ]; then
    cg2=1
  elif grep -qs cgroup2 /proc/mounts 2>/dev/null && find /sys/fs/cgroup -maxdepth 2 -name cgroup.freeze 2>/dev/null | grep -q .; then
    cg2=1
  fi
  tp=0
  if grep -qw TPROXY /proc/net/ip_tables_targets 2>/dev/null; then
    tp=1
  elif iptables -t mangle -j TPROXY --help >/dev/null 2>&1; then
    tp=1
  elif iptables -t mangle -L PREROUTING -n >/dev/null 2>&1 && zcat /proc/config.gz 2>/dev/null | grep -Eq \"CONFIG_NETFILTER_XT_TARGET_TPROXY=[ym]\"; then
    tp=1
  elif command -v nft >/dev/null 2>&1 && zcat /proc/config.gz 2>/dev/null | grep -Eq \"CONFIG_NFT_TPROXY=[ym]\"; then
    tp=1
  fi
  inst=0
  { [ -d /data/adb/modules/sandbox_guard ] || [ -x /data/adb/sandbox_guard/sandbox_guard ]; } && inst=1
  printf \"ROOT=%s\nROOTVER=%s\nZYGISK=%s\nCG2=%s\nTPROXY=%s\nINSTALLED=%s\nTS=%s\nPIF=%s\nHIDER=%s\nROOT_DENIED=0\n\" \"\$rmgr\" \"\$rver\" \"\$zy\" \"\$cg2\" \"\$tp\" \"\$inst\" \"\$ts\" \"\$pif\" \"\$hider\"
" 2>/dev/null || {
  echo "ROOT=none"
  if command -v su >/dev/null 2>&1 || pm list packages 2>/dev/null | grep -Eq "me\.weishu\.kernelsu|com\.topjohnwu\.magisk|me\.bmax\.apatch|io\.github\.huskydg\.magisk"; then
    echo "ROOT_DENIED=1"
  else
    echo "ROOT_DENIED=0"
  fi
}
')

JSON=$(printf '%s\n' "$RAW" | python3 -c '
import json, re, sys
kv = {}
for line in sys.stdin.read().splitlines():
    if "=" in line:
        k, v = line.split("=", 1)
        kv[k.strip()] = v.strip()
krel = kv.get("KREL", "")
m = re.match(r"^(\d+)\.(\d+)", krel)
kmaj, kmin = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
sdk = int(kv["SDK"]) if kv.get("SDK", "").isdigit() else 0
EXCLUDED_CLONE_USERS = {95, 150, 999}
work = set()
for part in kv.get("USERS_V", "").split("|"):
    um = re.search(r"id=(\d+).*(?:MANAGED_PROFILE|profile\.MANAGED)", part)
    if um:
        uid = int(um.group(1))
        if uid > 0 and uid not in EXCLUDED_CLONE_USERS:
            work.add(uid)
for part in kv.get("USERS_PM", "").split("|"):
    um = re.search(r"UserInfo\{(\d+):[^:]*:([0-9a-fA-F]+)\}", part)
    if um:
        uid = int(um.group(1))
        flags = int(um.group(2), 16)
        if uid > 0 and uid not in EXCLUDED_CLONE_USERS and (flags & 0x20) != 0:
            work.add(uid)
print(json.dumps({
    "schema_version": 1,
    "manufacturer": kv.get("MFG", ""),
    "brand": kv.get("BRAND", ""),
    "android_sdk": sdk,
    "android_release": kv.get("REL", ""),
    "cpu_abi": kv.get("ABI", ""),
    "kernel_release": krel,
    "kernel_major": kmaj,
    "kernel_minor": kmin,
    "oem_signals": {
        "miui_ui_version": kv.get("MIUI_UI", ""),
        "hyperos_version": kv.get("HYPEROS", ""),
        "oplusrom": kv.get("OPLUSROM", ""),
        "oneui": kv.get("ONEUI", ""),
        "build_flavor": kv.get("FLAVOR", ""),
    },
    "root_manager": kv.get("ROOT") or "none",
    "root_version": kv.get("ROOTVER", ""),
    "root_access_denied": kv.get("ROOT_DENIED") == "1",
    "zygisk_detected": kv.get("ZYGISK") == "1",
    "cgroup_v2_freeze": kv.get("CG2") == "1",
    "tproxy_capable": kv.get("TPROXY") == "1",
    "work_profile_users": sorted(work),
    "existing_guard_installed": kv.get("INSTALLED") == "1",
    "real_device_readiness": {
        "bootloader_verified_state": kv.get("VBSTATE", ""),
        "bootloader_flash_locked": kv.get("FLOCKED", ""),
        "build_tags": kv.get("BTAGS", ""),
        "adb_enabled": kv.get("ADB_EN") == "1",
        "accessibility_services_active": kv.get("ACC_ON") == "1",
        "trickystore_detected": kv.get("TS") == "1",
        "pif_detected": kv.get("PIF") == "1",
        "root_hider_detected": kv.get("HIDER") == "1",
    },
}, indent=2))
')

if [ -n "$OUT" ]; then
    mkdir -p -- "$(dirname -- "$OUT")"
    printf '%s\n' "$JSON" > "$OUT"
    echo "Wrote anonymized device profile to $OUT"
else
    printf '%s\n' "$JSON"
fi
