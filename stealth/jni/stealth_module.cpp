#include <sys/types.h>
#include "zygisk.hpp"
#include "stealth_logic.hpp"
#include "stealth_agent_dex.h"

#include <android/log.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <ifaddrs.h>
#include <link.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <utility>

#ifndef __NR_memfd_create
#define __NR_memfd_create 279
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifdef O_TMPFILE
constexpr int kOpenNeedsModeMask = O_CREAT | O_TMPFILE;
#else
constexpr int kOpenNeedsModeMask = O_CREAT;
#endif

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "SandboxStealth", __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, "SandboxStealth", __VA_ARGS__)

namespace {

constexpr const char* kStealthConfigPath = "/data/adb/sandbox_guard/stealth.json";
constexpr const char* kZygiskDisabledFlag = "/data/adb/modules/sandbox_guard/zygisk_disabled";
constexpr const char* kDisabledJson = "{\"enabled\":false}";
constexpr size_t kMaxConfigBytes = 16384;

stealth::StealthConfig g_cfg;
stealth::BakedProps g_baked_props;
char g_cfg_json[kMaxConfigBytes + 1] = {};
size_t g_cfg_json_len = 0;
bool g_is_phone_proc = false;
bool g_is_sandbox_app = false;
bool g_plt_hooked = false;
bool g_jni_hooked = false;
bool g_locale_jni_hooked = false;
volatile pid_t g_locale_hook_tid = 0;
int g_spoof_mcc = 0;
int g_spoof_mnc = 0;
uint32_t g_sandbox_ipv4_nbo = 0;

struct alignas(uint32_t) FakePropInfo {
    uint32_t serial;
    char value[stealth::kMaxBakedValueBytes];
    char name[96];
};
static_assert(stealth::kMaxBakedValueBytes == PROP_VALUE_MAX, "Baked property max size must match PROP_VALUE_MAX");
static_assert(sizeof(FakePropInfo) == sizeof(uint32_t) + PROP_VALUE_MAX + 96, "FakePropInfo layout mismatch");

FakePropInfo g_fake_props[stealth::kBakedPropCount] = {};

void populateFakeProps(const stealth::BakedProps& baked, FakePropInfo (&out)[stealth::kBakedPropCount]) {
    std::memset(out, 0, sizeof(out));
    for (size_t i = 0; i < stealth::kBakedPropCount; i++) {
        if (!baked.active[i]) continue;
        const char* pname = stealth::spoofablePropNameByIndex(static_cast<int>(i));
        if (!pname) continue;
        const size_t vlen = strnlen(baked.values[i], stealth::kMaxBakedValueBytes);
        const size_t nlen = strnlen(pname, sizeof(out[i].name) - 1);
        out[i].serial = (static_cast<uint32_t>(vlen & 0xFFu) << 24) | 2u;
        if (vlen > 0) {
            std::memcpy(out[i].value, baked.values[i], vlen);
        }
        out[i].value[vlen] = '\0';
        std::memcpy(out[i].name, pname, nlen);
        out[i].name[nlen] = '\0';
    }
}

constexpr size_t kPropSuffixCount = 14;
const char* const kPropTargetSuffixes[kPropSuffixCount] = {
    "/libandroid_runtime.so",
    "/libbase.so",
    "/libcutils.so",
    "/libutils.so",
    "/libart.so",
    "/libbinder.so",
    "/libandroid.so",
    "/libjavacore.so",
    "/libmedia.so",
    "/libmediandk.so",
    "/libstagefright.so",
    "/libhwui.so",
    "/libnetd_client.so",
    "/libopenjdk.so",
};
constexpr size_t kNetSuffixCount = 6;
const char* const kNetTargetSuffixes[kNetSuffixCount] = {
    "/libjavacore.so",
    "/libandroid_runtime.so",
    "/libnetd_client.so",
    "/libopenjdk.so",
    "/libbase.so",
    "/libcutils.so",
};
constexpr size_t kProcSuffixCount = 5;
const char* const kProcTargetSuffixes[kProcSuffixCount] = {
    "/libjavacore.so",
    "/libopenjdk.so",
    "/libandroid_runtime.so",
    "/libbase.so",
    "/libcutils.so",
};
constexpr size_t kMaxPropHookSlots = 48;
constexpr size_t kMaxNetHookSlots = 12;
constexpr size_t kMaxProcHookSlots = 16;

using FnGetIfAddrs = int (*)(struct ifaddrs** ifap);
using FnOpen = int (*)(const char* path, int flags, ...);
using FnOpen2 = int (*)(const char* path, int flags);
using FnFopen = FILE* (*)(const char* path, const char* mode);
using FnPropFind = const prop_info* (*)(const char* name);
using FnPropReadCb = void (*)(
    const prop_info* pi,
    void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial),
    void* cookie);
using FnPropRead = int (*)(const prop_info* pi, char* name, char* value);
using FnPropGet = int (*)(const char* name, char* value);

FnGetIfAddrs g_orig_getifaddrs[kMaxNetHookSlots] = {};
FnOpen g_orig_open[kMaxProcHookSlots] = {};
FnOpen2 g_orig_open2[kMaxProcHookSlots] = {};
FnFopen g_orig_fopen[kMaxProcHookSlots] = {};
FnPropFind g_orig_prop_find[kMaxPropHookSlots] = {};
FnPropReadCb g_orig_prop_cb[kMaxPropHookSlots] = {};
FnPropRead g_orig_prop_read[kMaxPropHookSlots] = {};
FnPropGet g_orig_prop_get[kMaxPropHookSlots] = {};

bool isTunnelIfaceName(const char* name) {
    if (!name) return false;
    return std::strncmp(name, "tun", 3) == 0 ||
           std::strncmp(name, "wg", 2) == 0 ||
           std::strncmp(name, "utun", 4) == 0 ||
           std::strncmp(name, "ppp", 3) == 0 ||
           std::strncmp(name, "tailscale", 9) == 0 ||
           std::strncmp(name, "dummy", 5) == 0 ||
           std::strncmp(name, "p2p", 3) == 0;
}

int hookGetifaddrsImpl(FnGetIfAddrs orig, struct ifaddrs** ifap) {
    if (!orig) {
        errno = ENOSYS;
        return -1;
    }
    int rc = orig(ifap);
    if (rc != 0 || !ifap || !*ifap) {
        return rc;
    }
    const uint32_t mask_nbo = htonl(0xFFFFFF00u);
    for (struct ifaddrs* cur = *ifap; cur != nullptr; cur = cur->ifa_next) {
        if (isTunnelIfaceName(cur->ifa_name)) {
            // Coalesce tunnel interfaces into "lo" with null addrs so NetworkInterface skips them while freeifaddrs() frees cleanly.
            cur->ifa_name[0] = 'l';
            cur->ifa_name[1] = 'o';
            cur->ifa_name[2] = '\0';
            cur->ifa_addr = nullptr;
            cur->ifa_netmask = nullptr;
            cur->ifa_ifu.ifu_broadaddr = nullptr;
            cur->ifa_flags = IFF_LOOPBACK | IFF_UP;
            continue;
        }
        if (!cur->ifa_addr) {
            continue;
        }
        if (cur->ifa_name && std::strcmp(cur->ifa_name, "lo") == 0) {
            continue;
        }
        const int fam = cur->ifa_addr->sa_family;
        if (fam == AF_PACKET) {
            auto* sll = reinterpret_cast<struct sockaddr_ll*>(cur->ifa_addr);
            sll->sll_halen = 0;
            std::memset(sll->sll_addr, 0, sizeof(sll->sll_addr));
        } else if (fam == AF_INET6) {
            // Preserve node pointer so freeifaddrs() releases every node without leaking memory.
            cur->ifa_addr = nullptr;
            cur->ifa_netmask = nullptr;
            cur->ifa_ifu.ifu_broadaddr = nullptr;
        } else if (fam == AF_INET && g_sandbox_ipv4_nbo != 0) {
            struct sockaddr_in sin{};
            std::memcpy(&sin, cur->ifa_addr, sizeof(sin));
            sin.sin_addr.s_addr = g_sandbox_ipv4_nbo;
            std::memcpy(cur->ifa_addr, &sin, sizeof(sin));
            if (cur->ifa_netmask != nullptr &&
                (cur->ifa_netmask->sa_family == AF_INET || cur->ifa_netmask->sa_family == AF_UNSPEC)) {
                struct sockaddr_in netmask_sin{};
                std::memcpy(&netmask_sin, cur->ifa_netmask, sizeof(netmask_sin));
                netmask_sin.sin_family = AF_INET;
                netmask_sin.sin_addr.s_addr = mask_nbo;
                std::memcpy(cur->ifa_netmask, &netmask_sin, sizeof(netmask_sin));
            }
            if ((cur->ifa_flags & IFF_BROADCAST) != 0 && cur->ifa_ifu.ifu_broadaddr != nullptr &&
                (cur->ifa_ifu.ifu_broadaddr->sa_family == AF_INET ||
                 cur->ifa_ifu.ifu_broadaddr->sa_family == AF_UNSPEC)) {
                struct sockaddr_in bcast_sin{};
                std::memcpy(&bcast_sin, cur->ifa_ifu.ifu_broadaddr, sizeof(bcast_sin));
                bcast_sin.sin_family = AF_INET;
                bcast_sin.sin_addr.s_addr = (g_sandbox_ipv4_nbo & mask_nbo) | ~mask_nbo;
                std::memcpy(cur->ifa_ifu.ifu_broadaddr, &bcast_sin, sizeof(bcast_sin));
            } else if ((cur->ifa_flags & IFF_POINTOPOINT) != 0 && cur->ifa_ifu.ifu_dstaddr != nullptr &&
                       (cur->ifa_ifu.ifu_dstaddr->sa_family == AF_INET ||
                        cur->ifa_ifu.ifu_dstaddr->sa_family == AF_UNSPEC)) {
                struct sockaddr_in dst_sin{};
                std::memcpy(&dst_sin, cur->ifa_ifu.ifu_dstaddr, sizeof(dst_sin));
                dst_sin.sin_family = AF_INET;
                const uint32_t gw_cand = (g_sandbox_ipv4_nbo & mask_nbo) | htonl(1u);
                dst_sin.sin_addr.s_addr = (g_sandbox_ipv4_nbo == gw_cand)
                    ? ((g_sandbox_ipv4_nbo & mask_nbo) | htonl(254u))
                    : gw_cand;
                std::memcpy(cur->ifa_ifu.ifu_dstaddr, &dst_sin, sizeof(dst_sin));
            }
        }
    }
    return rc;
}

template <size_t Slot>
int hook_getifaddrs_slot(struct ifaddrs** ifap) {
    return hookGetifaddrsImpl(g_orig_getifaddrs[Slot], ifap);
}

bool writeExact(int fd, const void* buf, size_t len);

int filterProcMapsFd(int raw_fd, int flags, bool is_smaps) {
    const int mfd = static_cast<int>(
        syscall(__NR_memfd_create, "", (flags & O_CLOEXEC) ? MFD_CLOEXEC : 0));
    if (mfd < 0) {
        return raw_fd;
    }

    char rbuf[4096];
    char line[4096];
    char wbuf[4096];
    size_t line_len = 0;
    bool line_overflow = false;
    size_t wlen = 0;
    bool skip_smaps_block = false;
    bool write_ok = true;

    auto flushWbuf = [&]() -> bool {
        if (wlen == 0) return true;
        const bool ok = writeExact(mfd, wbuf, wlen);
        wlen = 0;
        return ok;
    };

    auto emitLine = [&](const char* data, size_t len) -> bool {
        if (len == 0) return true;
        bool drop = false;
        if (is_smaps) {
            if (stealth::isSmapsHeaderLine(data, len)) {
                skip_smaps_block = stealth::shouldHideProcMapsLine(data, len);
            }
            drop = skip_smaps_block;
        } else {
            drop = stealth::shouldHideProcMapsLine(data, len);
        }
        if (drop) return true;
        if (len > sizeof(wbuf) - wlen) {
            if (!flushWbuf()) return false;
        }
        if (len > sizeof(wbuf)) {
            return writeExact(mfd, data, len);
        }
        std::memcpy(wbuf + wlen, data, len);
        wlen += len;
        return true;
    };

    while (write_ok) {
        ssize_t r = read(raw_fd, rbuf, sizeof(rbuf));
        if (r < 0) {
            if (errno == EINTR) continue;
            write_ok = false;
            break;
        }
        if (r == 0) break;

        for (ssize_t i = 0; i < r; i++) {
            const char c = rbuf[i];
            if (line_overflow) {
                if (c == '\n') {
                    line[sizeof(line) - 1] = '\n';
                    if (!emitLine(line, sizeof(line))) {
                        write_ok = false;
                        break;
                    }
                    line_len = 0;
                    line_overflow = false;
                }
                continue;
            }
            if (line_len < sizeof(line) - 1) {
                line[line_len++] = c;
            } else if (c == '\n') {
                line[line_len++] = '\n';
            } else {
                line_overflow = true;
                continue;
            }
            if (c == '\n') {
                if (!emitLine(line, line_len)) {
                    write_ok = false;
                    break;
                }
                line_len = 0;
            }
        }
    }

    if (write_ok && line_len > 0) {
        if (!emitLine(line, line_len)) {
            write_ok = false;
        }
    }
    if (write_ok && !flushWbuf()) {
        write_ok = false;
    }

    if (!write_ok) {
        close(mfd);
        (void)lseek(raw_fd, 0, SEEK_SET);
        return raw_fd;
    }
    close(raw_fd);
    if (lseek(mfd, 0, SEEK_SET) < 0) {
        // Impossible on empty memfd unless kernel fault; memfd still usable from offset 0.
    }
    return mfd;
}

int hookOpenImpl(FnOpen orig, const char* path, int flags, mode_t mode) {
    if (!orig) {
        errno = ENOSYS;
        return -1;
    }
    const int fd = (flags & kOpenNeedsModeMask) ? orig(path, flags, mode) : orig(path, flags);
    if (fd < 0 || (flags & O_ACCMODE) != O_RDONLY) {
        return fd;
    }
#ifdef O_PATH
    if ((flags & O_PATH) != 0) {
        return fd;
    }
#endif
    bool is_smaps = false;
    if (!stealth::isSanitizedProcMapsPath(path, &is_smaps)) {
        return fd;
    }
    return filterProcMapsFd(fd, flags, is_smaps);
}

int hookOpen2Impl(FnOpen2 orig, const char* path, int flags) {
    if (!orig) {
        errno = ENOSYS;
        return -1;
    }
    const int fd = orig(path, flags);
    if (fd < 0 || (flags & O_ACCMODE) != O_RDONLY) {
        return fd;
    }
#ifdef O_PATH
    if ((flags & O_PATH) != 0) {
        return fd;
    }
#endif
    bool is_smaps = false;
    if (!stealth::isSanitizedProcMapsPath(path, &is_smaps)) {
        return fd;
    }
    return filterProcMapsFd(fd, flags, is_smaps);
}

FILE* hookFopenImpl(FnFopen orig, const char* path, const char* mode) {
    if (!orig) {
        errno = ENOSYS;
        return nullptr;
    }
    bool is_smaps = false;
    if (!mode || mode[0] != 'r' || std::strchr(mode, '+') != nullptr ||
        !stealth::isSanitizedProcMapsPath(path, &is_smaps)) {
        return orig(path, mode);
    }
    const int open_flags = O_RDONLY | (std::strchr(mode, 'e') != nullptr ? O_CLOEXEC : 0);
    const int raw_fd = ::open(path, open_flags);
    if (raw_fd < 0) {
        return orig(path, mode);
    }
    const int mfd = filterProcMapsFd(raw_fd, open_flags, is_smaps);
    FILE* fp = ::fdopen(mfd, mode);
    if (!fp) {
        close(mfd);
        return orig(path, mode);
    }
    return fp;
}

template <size_t Slot>
int hook_open_slot(const char* path, int flags, ...) {
    mode_t mode = 0;
    if (flags & kOpenNeedsModeMask) {
        va_list ap;
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, unsigned int));
        va_end(ap);
    }
    return hookOpenImpl(g_orig_open[Slot], path, flags, mode);
}

template <size_t Slot>
int hook_open2_slot(const char* path, int flags) {
    return hookOpen2Impl(g_orig_open2[Slot], path, flags);
}

template <size_t Slot>
FILE* hook_fopen_slot(const char* path, const char* mode) {
    return hookFopenImpl(g_orig_fopen[Slot], path, mode);
}

struct PropCbCtx {
    void (*orig_cb)(void* cookie, const char* name, const char* value, uint32_t serial);
    void* orig_cookie;
};

void wrappedPropReadCallback(void* raw_ctx, const char* name, const char* value, uint32_t serial) {
    auto* ctx = static_cast<PropCbCtx*>(raw_ctx);
    char stack_buf[PROP_VALUE_MAX];
    const char* spoofed = nullptr;
    if (stealth::lookupSpoofedPropertyIntoBuf(g_baked_props, name, value, stack_buf, sizeof(stack_buf), &spoofed)) {
        ctx->orig_cb(ctx->orig_cookie, name, spoofed, serial);
        return;
    }
    ctx->orig_cb(ctx->orig_cookie, name, value, serial);
}

const prop_info* hookPropFindImpl(FnPropFind orig, const char* name) {
    const int idx = stealth::spoofablePropIndex(name);
    if (idx >= 0 && g_baked_props.active[idx] && !stealth::isMultiSimCarrierSlot(idx)) {
        return reinterpret_cast<const prop_info*>(&g_fake_props[idx]);
    }
    const prop_info* pi = orig ? orig(name) : nullptr;
    if (pi != nullptr) {
        return pi;
    }
    if (idx >= 0 && g_baked_props.active[idx]) {
        return reinterpret_cast<const prop_info*>(&g_fake_props[idx]);
    }
    return nullptr;
}

template <size_t Slot>
const prop_info* hook_prop_find_slot(const char* name) {
    return hookPropFindImpl(g_orig_prop_find[Slot], name);
}

void hookPropReadCbImpl(
    FnPropReadCb orig,
    const prop_info* pi,
    void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial),
    void* cookie) {
    if (!callback) return;
    if (pi != nullptr) {
        const uintptr_t ptr = reinterpret_cast<uintptr_t>(pi);
        const uintptr_t begin = reinterpret_cast<uintptr_t>(&g_fake_props[0]);
        const uintptr_t end = reinterpret_cast<uintptr_t>(&g_fake_props[stealth::kBakedPropCount]);
        if (ptr >= begin && ptr < end && ((ptr - begin) % sizeof(FakePropInfo)) == 0) {
            const size_t idx = static_cast<size_t>((ptr - begin) / sizeof(FakePropInfo));
            if (g_baked_props.active[idx] && g_fake_props[idx].name[0] != '\0') {
                callback(cookie, g_fake_props[idx].name, g_fake_props[idx].value, g_fake_props[idx].serial);
                return;
            }
        }
    }
    if (!orig) return;
    PropCbCtx ctx{callback, cookie};
    orig(pi, wrappedPropReadCallback, &ctx);
}

template <size_t Slot>
void hook_prop_read_cb_slot(
    const prop_info* pi,
    void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial),
    void* cookie) {
    hookPropReadCbImpl(g_orig_prop_cb[Slot], pi, callback, cookie);
}

int hookPropReadImpl(FnPropRead orig, const prop_info* pi, char* name, char* value) {
    if (pi != nullptr) {
        const uintptr_t ptr = reinterpret_cast<uintptr_t>(pi);
        const uintptr_t begin = reinterpret_cast<uintptr_t>(&g_fake_props[0]);
        const uintptr_t end = reinterpret_cast<uintptr_t>(&g_fake_props[stealth::kBakedPropCount]);
        if (ptr >= begin && ptr < end && ((ptr - begin) % sizeof(FakePropInfo)) == 0) {
            const size_t idx = static_cast<size_t>((ptr - begin) / sizeof(FakePropInfo));
            if (g_baked_props.active[idx] && g_fake_props[idx].name[0] != '\0') {
                if (name) {
                    const size_t nlen = std::strlen(g_fake_props[idx].name);
                    std::memcpy(name, g_fake_props[idx].name, nlen + 1);
                }
                const size_t vlen = std::strlen(g_fake_props[idx].value);
                if (value && vlen < PROP_VALUE_MAX) {
                    std::memcpy(value, g_fake_props[idx].value, vlen + 1);
                    return static_cast<int>(vlen);
                }
                if (value) value[0] = '\0';
                return 0;
            }
        }
    }
    if (!orig) {
        if (name) name[0] = '\0';
        if (value) value[0] = '\0';
        return 0;
    }
    char local_name[128] = {};
    char local_val[PROP_VALUE_MAX] = {};
    int len = orig(pi, name ? name : local_name, value ? value : local_val);
    const char* resolved_name = name ? name : local_name;
    const char* resolved_val = value ? value : local_val;
    char stack_buf[PROP_VALUE_MAX];
    const char* spoofed = nullptr;
    if (stealth::lookupSpoofedPropertyIntoBuf(g_baked_props, resolved_name, resolved_val, stack_buf, sizeof(stack_buf), &spoofed) && spoofed) {
        const size_t slen = std::strlen(spoofed);
        if (slen < PROP_VALUE_MAX) {
            if (value) {
                std::memcpy(value, spoofed, slen + 1);
            }
            return static_cast<int>(slen);
        }
    }
    return len;
}

template <size_t Slot>
int hook_prop_read_slot(const prop_info* pi, char* name, char* value) {
    return hookPropReadImpl(g_orig_prop_read[Slot], pi, name, value);
}

int hookPropGetImpl(FnPropGet orig, const char* name, char* value) {
    if (!name || !value) {
        return orig ? orig(name, value) : 0;
    }
    const int idx = stealth::spoofablePropIndex(name);
    if (idx >= 0 && g_baked_props.active[idx]) {
        if (stealth::isMultiSimCarrierSlot(idx)) {
            char orig_val[PROP_VALUE_MAX] = {};
            if (orig) {
                orig(name, orig_val);
            }
            char stack_buf[PROP_VALUE_MAX];
            const char* res = nullptr;
            if (stealth::lookupSpoofedPropertyIntoBuf(
                    g_baked_props, name, orig_val, stack_buf, sizeof(stack_buf), &res) && res) {
                const size_t len = std::strlen(res);
                if (len < PROP_VALUE_MAX) {
                    std::memcpy(value, res, len + 1);
                    return static_cast<int>(len);
                }
            }
        }
        const size_t fallback_len = strnlen(g_baked_props.values[idx], stealth::kMaxBakedValueBytes);
        if (fallback_len < PROP_VALUE_MAX) {
            std::memcpy(value, g_baked_props.values[idx], fallback_len + 1);
            return static_cast<int>(fallback_len);
        }
        value[0] = '\0';
        return 0;
    }
    return orig ? orig(name, value) : 0;
}

template <size_t Slot>
int hook_prop_get_slot(const char* name, char* value) {
    return hookPropGetImpl(g_orig_prop_get[Slot], name, value);
}

template <size_t... Is>
void fillPropHookTables(
    FnPropFind (&find_hooks)[kMaxPropHookSlots],
    FnPropReadCb (&cb_hooks)[kMaxPropHookSlots],
    FnPropRead (&read_hooks)[kMaxPropHookSlots],
    FnPropGet (&get_hooks)[kMaxPropHookSlots],
    std::index_sequence<Is...>) {
    ((find_hooks[Is] = hook_prop_find_slot<Is>,
      cb_hooks[Is] = hook_prop_read_cb_slot<Is>,
      read_hooks[Is] = hook_prop_read_slot<Is>,
      get_hooks[Is] = hook_prop_get_slot<Is>), ...);
}

template <size_t... Is>
void fillNetHookTable(FnGetIfAddrs (&net_hooks)[kMaxNetHookSlots], std::index_sequence<Is...>) {
    ((net_hooks[Is] = hook_getifaddrs_slot<Is>), ...);
}

template <size_t... Is>
void fillProcHookTables(
    FnOpen (&open_hooks)[kMaxProcHookSlots],
    FnOpen2 (&open2_hooks)[kMaxProcHookSlots],
    FnFopen (&fopen_hooks)[kMaxProcHookSlots],
    std::index_sequence<Is...>) {
    ((open_hooks[Is] = hook_open_slot<Is>,
      open2_hooks[Is] = hook_open2_slot<Is>,
      fopen_hooks[Is] = hook_fopen_slot<Is>), ...);
}

bool writeExact(int fd, const void* buf, size_t len) {
    const auto* p = static_cast<const uint8_t*>(buf);
    size_t sent = 0;
    while (sent < len) {
        ssize_t w = write(fd, p + sent, len - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        sent += static_cast<size_t>(w);
    }
    return true;
}

bool readExact(int fd, void* buf, size_t len) {
    auto* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < len) {
        ssize_t r = read(fd, p + got, len - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (r == 0) return false;
        got += static_cast<size_t>(r);
    }
    return true;
}

size_t readSafeRootConfig(char* out_buf, size_t out_cap) {
    auto fallbackDisabled = [&]() -> size_t {
        const size_t dlen = std::strlen(kDisabledJson);
        if (dlen < out_cap) {
            std::memcpy(out_buf, kDisabledJson, dlen + 1);
            return dlen;
        }
        return 0;
    };
    if (!out_buf || out_cap <= std::strlen(kDisabledJson)) {
        return 0;
    }
    if (access(kZygiskDisabledFlag, F_OK) == 0) {
        return fallbackDisabled();
    }
    int fd = open(kStealthConfigPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return fallbackDisabled();
    }
    struct stat st{};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        st.st_size <= 0 || static_cast<size_t>(st.st_size) > kMaxConfigBytes ||
        static_cast<size_t>(st.st_size) >= out_cap) {
        close(fd);
        return fallbackDisabled();
    }
    const size_t want = static_cast<size_t>(st.st_size);
    size_t total = 0;
    while (total < want) {
        ssize_t r = read(fd, out_buf + total, want - total);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return fallbackDisabled();
        }
        if (r == 0) break;
        total += static_cast<size_t>(r);
    }
    close(fd);
    if (total == 0) {
        return fallbackDisabled();
    }
    out_buf[total] = '\0';
    return total;
}

void companionHandler(int client_fd) {
    char json_buf[kMaxConfigBytes + 1];
    size_t len_sz = readSafeRootConfig(json_buf, sizeof(json_buf));
    if (len_sz == 0 || len_sz > kMaxConfigBytes) {
        len_sz = std::strlen(kDisabledJson);
        std::memcpy(json_buf, kDisabledJson, len_sz + 1);
    }
    uint32_t len = static_cast<uint32_t>(len_sz);
    if (writeExact(client_fd, &len, sizeof(len))) {
        (void)writeExact(client_fd, json_buf, len_sz);
    }
    close(client_fd);
}

bool fetchConfigFromCompanion(zygisk::Api* api, char* out_buf, size_t out_cap, size_t& out_len) {
    out_len = 0;
    if (!api || !out_buf || out_cap <= kMaxConfigBytes) {
        return false;
    }
    int fd = api->connectCompanion();
    if (fd < 0) {
        return false;
    }
    struct timeval tv{};
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    uint32_t len = 0;
    if (!readExact(fd, &len, sizeof(len)) || len == 0 || len > kMaxConfigBytes) {
        close(fd);
        return false;
    }
    bool ok = readExact(fd, out_buf, len);
    close(fd);
    if (!ok) {
        out_buf[0] = '\0';
        return false;
    }
    out_buf[len] = '\0';
    out_len = len;
    return true;
}

struct ResolvedTarget {
    dev_t dev;
    ino_t inode;
};

struct TargetList {
    ResolvedTarget items[kMaxPropHookSlots];
    size_t count = 0;
    size_t cap = 0;
};

bool endsWithAnySuffix(const char* path, size_t plen, const char* const* suffixes, size_t suffix_count) {
    if (!path || !suffixes) return false;
    for (size_t i = 0; i < suffix_count; i++) {
        const char* s = suffixes[i];
        if (!s) continue;
        const size_t slen = std::strlen(s);
        if (slen > 0 && plen >= slen && std::memcmp(path + plen - slen, s, slen) == 0) {
            return true;
        }
    }
    return false;
}

void appendUniqueTarget(TargetList& list, dev_t dev, ino_t inode) {
    if (list.count >= list.cap) return;
    for (size_t i = 0; i < list.count; i++) {
        if (list.items[i].dev == dev && list.items[i].inode == inode) {
            return;
        }
    }
    list.items[list.count++] = ResolvedTarget{dev, inode};
}

void insertPriorityTarget(TargetList& list, dev_t dev, ino_t inode) {
    for (size_t i = 0; i < list.count; i++) {
        if (list.items[i].dev == dev && list.items[i].inode == inode) {
            return;
        }
    }
    if (list.cap == 0) return;
    size_t move_end = list.count < list.cap ? list.count : list.cap - 1;
    for (size_t i = move_end; i > 0; i--) {
        list.items[i] = list.items[i - 1];
    }
    list.items[0] = ResolvedTarget{dev, inode};
    if (list.count < list.cap) {
        list.count++;
    }
}

struct PhdrMultiCtx {
    TargetList* prop_list;
    bool want_props;
    bool have_android_runtime;
    TargetList* net_list;
    bool want_net;
    TargetList* proc_list;
    bool want_proc;
};

int phdrMultiMatchCallback(struct dl_phdr_info* info, [[maybe_unused]] size_t size, void* raw_ctx) {
    auto* ctx = static_cast<PhdrMultiCtx*>(raw_ctx);
    if (!info || !info->dlpi_name || info->dlpi_name[0] != '/') {
        return 0;
    }
    const size_t plen = std::strlen(info->dlpi_name);
    const bool is_runtime = ctx->want_props && endsWithAnySuffix(info->dlpi_name, plen, &kPropTargetSuffixes[0], 1);
    const bool match_prop = is_runtime || (ctx->want_props && ctx->prop_list->count < ctx->prop_list->cap &&
        endsWithAnySuffix(info->dlpi_name, plen, kPropTargetSuffixes, kPropSuffixCount));
    const bool match_net = ctx->want_net && ctx->net_list->count < ctx->net_list->cap &&
        endsWithAnySuffix(info->dlpi_name, plen, kNetTargetSuffixes, kNetSuffixCount);
    const bool match_proc = ctx->want_proc && ctx->proc_list->count < ctx->proc_list->cap &&
        endsWithAnySuffix(info->dlpi_name, plen, kProcTargetSuffixes, kProcSuffixCount);
    if (!match_prop && !match_net && !match_proc) {
        return 0;
    }
    struct stat st{};
    if (stat(info->dlpi_name, &st) == 0 && S_ISREG(st.st_mode)) {
        if (is_runtime) {
            insertPriorityTarget(*ctx->prop_list, st.st_dev, st.st_ino);
            ctx->have_android_runtime = true;
        } else if (match_prop) {
            appendUniqueTarget(*ctx->prop_list, st.st_dev, st.st_ino);
        }
        if (match_net) appendUniqueTarget(*ctx->net_list, st.st_dev, st.st_ino);
        if (match_proc) appendUniqueTarget(*ctx->proc_list, st.st_dev, st.st_ino);
    }
    const bool props_full = !ctx->want_props || (ctx->prop_list->count >= ctx->prop_list->cap && ctx->have_android_runtime);
    const bool net_full = !ctx->want_net || ctx->net_list->count >= ctx->net_list->cap;
    const bool proc_full = !ctx->want_proc || ctx->proc_list->count >= ctx->proc_list->cap;
    return (props_full && net_full && proc_full) ? 1 : 0;
}

// Single-pass /proc/self/maps resolution collects up to kMaxPropHookSlots unique (dev, ino)
// prop/net/proc library mappings (always prioritizing libandroid_runtime.so ahead of APEX duplicates).
void findLibrariesFromMaps(
    bool want_props, TargetList& prop_list,
    bool want_net, TargetList& net_list,
    bool want_proc, TargetList& proc_list) {
    prop_list.count = 0;
    prop_list.cap = kMaxPropHookSlots;
    net_list.count = 0;
    net_list.cap = kMaxNetHookSlots;
    proc_list.count = 0;
    proc_list.cap = kMaxProcHookSlots;
    if (!want_props && !want_net && !want_proc) return;
    bool have_android_runtime = false;

    FILE* fp = std::fopen("/proc/self/maps", "re");
    if (fp) {
        char line[1024];
        while (std::fgets(line, sizeof(line), fp) != nullptr) {
            const size_t llen = std::strlen(line);
            if (llen == sizeof(line) - 1 && line[llen - 1] != '\n') {
                int ch;
                while ((ch = std::fgetc(fp)) != EOF && ch != '\n') {}
            }
            unsigned long long start = 0, end = 0, offset = 0, inode = 0;
            unsigned int major_id = 0, minor_id = 0;
            char perms[8] = {};
            int path_offset = 0;
            if (std::sscanf(line, "%llx-%llx %7s %llx %x:%x %llu %n",
                            &start, &end, perms, &offset, &major_id, &minor_id, &inode, &path_offset) >= 7) {
                if (inode == 0 || path_offset <= 0) continue;
                const char* path = line + path_offset;
                if (path[0] != '/') continue;
                size_t plen = std::strlen(path);
                while (plen > 0 && (path[plen - 1] == '\n' || path[plen - 1] == '\r')) plen--;
                const dev_t dev = makedev(major_id, minor_id);
                const ino_t ino = static_cast<ino_t>(inode);
                if (want_props && endsWithAnySuffix(path, plen, &kPropTargetSuffixes[0], 1)) {
                    insertPriorityTarget(prop_list, dev, ino);
                    have_android_runtime = true;
                } else if (want_props && prop_list.count < prop_list.cap &&
                           endsWithAnySuffix(path, plen, kPropTargetSuffixes, kPropSuffixCount)) {
                    appendUniqueTarget(prop_list, dev, ino);
                }
                if (want_net && net_list.count < net_list.cap &&
                    endsWithAnySuffix(path, plen, kNetTargetSuffixes, kNetSuffixCount)) {
                    appendUniqueTarget(net_list, dev, ino);
                }
                if (want_proc && proc_list.count < proc_list.cap &&
                    endsWithAnySuffix(path, plen, kProcTargetSuffixes, kProcSuffixCount)) {
                    appendUniqueTarget(proc_list, dev, ino);
                }
                const bool props_full = !want_props || (prop_list.count >= prop_list.cap && have_android_runtime);
                const bool net_full = !want_net || net_list.count >= net_list.cap;
                const bool proc_full = !want_proc || proc_list.count >= proc_list.cap;
                if (props_full && net_full && proc_full) {
                    break;
                }
            }
        }
        std::fclose(fp);
    }

    if ((want_props && (!have_android_runtime || prop_list.count == 0)) ||
        (want_net && net_list.count == 0) ||
        (want_proc && proc_list.count == 0)) {
        PhdrMultiCtx ctx{&prop_list, want_props, have_android_runtime, &net_list, want_net, &proc_list, want_proc};
        dl_iterate_phdr(phdrMultiMatchCallback, &ctx);
    }
}

void clearJniException(JNIEnv* env) {
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

jstring newJniStringSafe(JNIEnv* env, const char* s, size_t len) {
    if (!env || !s) return nullptr;
    bool ascii_safe = true;
    for (size_t i = 0; i < len; i++) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == 0 || c >= 0x80) {
            ascii_safe = false;
            break;
        }
    }
    if (ascii_safe) {
        jstring out = env->NewStringUTF(s);
        if (!out || env->ExceptionCheck()) {
            clearJniException(env);
            return nullptr;
        }
        return out;
    }
    jbyteArray arr = env->NewByteArray(static_cast<jsize>(len));
    if (!arr || env->ExceptionCheck()) {
        clearJniException(env);
        return nullptr;
    }
    env->SetByteArrayRegion(arr, 0, static_cast<jsize>(len),
                            reinterpret_cast<const jbyte*>(s));
    if (env->ExceptionCheck()) {
        clearJniException(env);
        env->DeleteLocalRef(arr);
        return nullptr;
    }
    jclass str_cls = env->FindClass("java/lang/String");
    if (!str_cls || env->ExceptionCheck()) {
        clearJniException(env);
        env->DeleteLocalRef(arr);
        return nullptr;
    }
    jmethodID ctor = env->GetMethodID(str_cls, "<init>", "([BLjava/lang/String;)V");
    jstring utf8 = env->NewStringUTF("UTF-8");
    if (!ctor || !utf8 || env->ExceptionCheck()) {
        clearJniException(env);
        if (utf8) env->DeleteLocalRef(utf8);
        env->DeleteLocalRef(str_cls);
        env->DeleteLocalRef(arr);
        return nullptr;
    }
    auto res = static_cast<jstring>(env->NewObject(str_cls, ctor, arr, utf8));
    env->DeleteLocalRef(utf8);
    env->DeleteLocalRef(str_cls);
    env->DeleteLocalRef(arr);
    if (!res || env->ExceptionCheck()) {
        clearJniException(env);
        return nullptr;
    }
    return res;
}

jstring newJniStringSafe(JNIEnv* env, const char* s) {
    return s ? newJniStringSafe(env, s, std::strlen(s)) : nullptr;
}

void injectDexAndInstallSystemHook(JNIEnv* env, const char* process_name) {
    if (!env || g_cfg_json_len == 0) return;
    if (env->PushLocalFrame(32) != 0) {
        clearJniException(env);
        return;
    }

    jclass cl_cls = env->FindClass("java/lang/ClassLoader");
    if (!cl_cls) { clearJniException(env); env->PopLocalFrame(nullptr); return; }
    jmethodID get_boot = env->GetStaticMethodID(cl_cls, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    if (!get_boot) { clearJniException(env); env->PopLocalFrame(nullptr); return; }
    jobject parent_cl = env->CallStaticObjectMethod(cl_cls, get_boot);
    if (env->ExceptionCheck() || !parent_cl) { clearJniException(env); env->PopLocalFrame(nullptr); return; }

    jbyteArray dex_bytes = env->NewByteArray(static_cast<jsize>(kStealthAgentDexLen));
    if (!dex_bytes) { clearJniException(env); env->PopLocalFrame(nullptr); return; }
    env->SetByteArrayRegion(dex_bytes, 0, static_cast<jsize>(kStealthAgentDexLen),
                            reinterpret_cast<const jbyte*>(kStealthAgentDex));
    if (env->ExceptionCheck()) { clearJniException(env); env->PopLocalFrame(nullptr); return; }

    jclass bb_cls = env->FindClass("java/nio/ByteBuffer");
    if (!bb_cls || env->ExceptionCheck()) { clearJniException(env); env->PopLocalFrame(nullptr); return; }
    jmethodID wrap_mid = env->GetStaticMethodID(bb_cls, "wrap", "([B)Ljava/nio/ByteBuffer;");
    if (!wrap_mid || env->ExceptionCheck()) { clearJniException(env); env->PopLocalFrame(nullptr); return; }
    jobject dex_buf = env->CallStaticObjectMethod(bb_cls, wrap_mid, dex_bytes);
    if (env->ExceptionCheck() || !dex_buf) { clearJniException(env); env->PopLocalFrame(nullptr); return; }

    jclass loader_cls = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (!loader_cls || env->ExceptionCheck()) { clearJniException(env); env->PopLocalFrame(nullptr); return; }
    jmethodID ctor_mid = env->GetMethodID(loader_cls, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (!ctor_mid || env->ExceptionCheck()) { clearJniException(env); env->PopLocalFrame(nullptr); return; }
    jobject mem_cl = env->NewObject(loader_cls, ctor_mid, dex_buf, parent_cl);
    if (env->ExceptionCheck() || !mem_cl) { clearJniException(env); env->PopLocalFrame(nullptr); return; }

    jmethodID load_mid = env->GetMethodID(cl_cls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (!load_mid || env->ExceptionCheck()) { clearJniException(env); env->PopLocalFrame(nullptr); return; }
    jstring hook_name = newJniStringSafe(env, "com.sandbox.stealth.SystemServerHook");
    if (!hook_name) { clearJniException(env); env->PopLocalFrame(nullptr); return; }
    auto hook_cls = static_cast<jclass>(env->CallObjectMethod(mem_cl, load_mid, hook_name));
    if (env->ExceptionCheck() || !hook_cls) { clearJniException(env); env->PopLocalFrame(nullptr); return; }

    jmethodID install_mid = env->GetStaticMethodID(
        hook_cls, "install", "(Ljava/lang/String;Ljava/lang/String;)Z");
    if (!install_mid || env->ExceptionCheck()) { clearJniException(env); env->PopLocalFrame(nullptr); return; }

    jstring json_str = newJniStringSafe(env, g_cfg_json);
    jstring proc_str = newJniStringSafe(env, process_name ? process_name : "");
    if (!json_str || !proc_str || env->ExceptionCheck()) {
        clearJniException(env);
        env->PopLocalFrame(nullptr);
        return;
    }
    jboolean ok = env->CallStaticBooleanMethod(hook_cls, install_mid, json_str, proc_str);
    if (env->ExceptionCheck()) {
        clearJniException(env);
        env->PopLocalFrame(nullptr);
        LOGW("SystemServerHook.install threw exception in %s", process_name);
        return;
    }
    env->PopLocalFrame(nullptr);
    LOGI("SystemServerHook.install(%s, oem=%s) => %s", process_name, stealth::kOemProfileName, ok ? "true" : "false");
}

void applyJavaLocaleOnly(JNIEnv* env, const stealth::StealthConfig& cfg) {
    if (!env || !cfg.spoof_locale || cfg.locale.empty()) return;
    if (env->PushLocalFrame(24) != 0) {
        clearJniException(env);
        return;
    }

    jclass loc_cls = env->FindClass("java/util/Locale");
    if (loc_cls && !env->ExceptionCheck()) {
        jmethodID get_def = env->GetStaticMethodID(loc_cls, "getDefault", "()Ljava/util/Locale;");
        jmethodID to_tag = env->GetMethodID(loc_cls, "toLanguageTag", "()Ljava/lang/String;");
        if (get_def && to_tag && !env->ExceptionCheck()) {
            jobject cur_loc = env->CallStaticObjectMethod(loc_cls, get_def);
            if (!env->ExceptionCheck() && cur_loc) {
                auto cur_tag_j = static_cast<jstring>(env->CallObjectMethod(cur_loc, to_tag));
                if (!env->ExceptionCheck() && cur_tag_j) {
                    const char* cur_tag = env->GetStringUTFChars(cur_tag_j, nullptr);
                    bool already_matches = cur_tag != nullptr && strcasecmp(cur_tag, cfg.locale.c_str()) == 0;
                    if (cur_tag) {
                        env->ReleaseStringUTFChars(cur_tag_j, cur_tag);
                    }
                    if (already_matches) {
                        env->PopLocalFrame(nullptr);
                        return;
                    }
                }
            }
        }
        clearJniException(env);

        jmethodID for_tag = env->GetStaticMethodID(loc_cls, "forLanguageTag", "(Ljava/lang/String;)Ljava/util/Locale;");
        jmethodID set_def = env->GetStaticMethodID(loc_cls, "setDefault", "(Ljava/util/Locale;)V");
        if (for_tag && set_def && !env->ExceptionCheck()) {
            jstring tag = newJniStringSafe(env, cfg.locale.c_str(), cfg.locale.size());
            if (tag) {
                jobject loc_obj = env->CallStaticObjectMethod(loc_cls, for_tag, tag);
                if (!env->ExceptionCheck() && loc_obj) {
                    env->CallStaticVoidMethod(loc_cls, set_def, loc_obj);
                }
            }
        }
    }
    clearJniException(env);

    jclass uloc_cls = env->FindClass("android/icu/util/ULocale");
    if (uloc_cls && !env->ExceptionCheck()) {
        jmethodID for_utag = env->GetStaticMethodID(uloc_cls, "forLanguageTag", "(Ljava/lang/String;)Landroid/icu/util/ULocale;");
        jmethodID set_udef = env->GetStaticMethodID(uloc_cls, "setDefault", "(Landroid/icu/util/ULocale;)V");
        if (for_utag && set_udef && !env->ExceptionCheck()) {
            jstring tag = newJniStringSafe(env, cfg.locale.c_str(), cfg.locale.size());
            if (tag) {
                jobject uloc_obj = env->CallStaticObjectMethod(uloc_cls, for_utag, tag);
                if (!env->ExceptionCheck() && uloc_obj) {
                    env->CallStaticVoidMethod(uloc_cls, set_udef, uloc_obj);
                }
            }
        }
    }
    clearJniException(env);

    jclass ll_cls = env->FindClass("android/os/LocaleList");
    if (ll_cls && !env->ExceptionCheck()) {
        jmethodID for_tags = env->GetStaticMethodID(ll_cls, "forLanguageTags", "(Ljava/lang/String;)Landroid/os/LocaleList;");
        jmethodID set_ll = env->GetStaticMethodID(ll_cls, "setDefault", "(Landroid/os/LocaleList;)V");
        if (for_tags && set_ll && !env->ExceptionCheck()) {
            jstring tags = newJniStringSafe(env, cfg.locale.c_str(), cfg.locale.size());
            if (tags) {
                jobject ll_obj = env->CallStaticObjectMethod(ll_cls, for_tags, tags);
                if (!env->ExceptionCheck() && ll_obj) {
                    env->CallStaticVoidMethod(ll_cls, set_ll, ll_obj);
                }
            }
        }
    }
    clearJniException(env);

    // Clear stale Zygote pre-fork user.language/country/region system properties.
    stealth::FixedStr<32> lang;
    stealth::FixedStr<32> country;
    stealth::detail::splitLocaleTag(cfg.locale, cfg.device_region, lang, country);
    jclass sys_cls = env->FindClass("java/lang/System");
    if (sys_cls && !env->ExceptionCheck()) {
        jmethodID set_prop = env->GetStaticMethodID(
            sys_cls, "setProperty", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
        if (set_prop && !env->ExceptionCheck()) {
            auto setSysProp = [&](const char* k, const char* v, size_t vlen) {
                if (!v || vlen == 0) return;
                jstring jk = newJniStringSafe(env, k);
                jstring jv = newJniStringSafe(env, v, vlen);
                jobject prev = nullptr;
                if (jk && jv && !env->ExceptionCheck()) {
                    prev = env->CallStaticObjectMethod(sys_cls, set_prop, jk, jv);
                }
                clearJniException(env);
                if (prev) env->DeleteLocalRef(prev);
                if (jk) env->DeleteLocalRef(jk);
                if (jv) env->DeleteLocalRef(jv);
            };
            setSysProp("user.language", lang.c_str(), lang.size());
            setSysProp("user.country", country.c_str(), country.size());
            setSysProp("user.region", country.c_str(), country.size());
        }
    }
    clearJniException(env);
    env->PopLocalFrame(nullptr);
}

void applyJavaTimezoneAndLocale(JNIEnv* env, const stealth::StealthConfig& cfg) {
    if (!env) return;
    if (env->PushLocalFrame(16) != 0) {
        clearJniException(env);
        return;
    }

    if (cfg.spoof_timezone && !cfg.timezone.empty()) {
        jclass tz_cls = env->FindClass("java/util/TimeZone");
        if (tz_cls && !env->ExceptionCheck()) {
            jmethodID get_tz = env->GetStaticMethodID(tz_cls, "getTimeZone", "(Ljava/lang/String;)Ljava/util/TimeZone;");
            if (get_tz && !env->ExceptionCheck()) {
                jmethodID set_tz = env->GetStaticMethodID(tz_cls, "setDefault", "(Ljava/util/TimeZone;)V");
                if (set_tz && !env->ExceptionCheck()) {
                    jstring tz_id = newJniStringSafe(env, cfg.timezone.c_str(), cfg.timezone.size());
                    if (tz_id) {
                        jobject tz_obj = env->CallStaticObjectMethod(tz_cls, get_tz, tz_id);
                        if (!env->ExceptionCheck() && tz_obj) {
                            env->CallStaticVoidMethod(tz_cls, set_tz, tz_obj);
                        }
                    }
                }
            }
        }
        clearJniException(env);

        jclass icu_tz_cls = env->FindClass("android/icu/util/TimeZone");
        if (icu_tz_cls && !env->ExceptionCheck()) {
            jmethodID get_icu_tz = env->GetStaticMethodID(icu_tz_cls, "getTimeZone", "(Ljava/lang/String;)Landroid/icu/util/TimeZone;");
            if (get_icu_tz && !env->ExceptionCheck()) {
                jmethodID set_icu_tz = env->GetStaticMethodID(icu_tz_cls, "setDefault", "(Landroid/icu/util/TimeZone;)V");
                if (set_icu_tz && !env->ExceptionCheck()) {
                    jstring tz_id = newJniStringSafe(env, cfg.timezone.c_str(), cfg.timezone.size());
                    if (tz_id) {
                        jobject tz_obj = env->CallStaticObjectMethod(icu_tz_cls, get_icu_tz, tz_id);
                        if (!env->ExceptionCheck() && tz_obj) {
                            env->CallStaticVoidMethod(icu_tz_cls, set_icu_tz, tz_obj);
                        }
                    }
                }
            }
        }
        clearJniException(env);

        jclass sys_cls = env->FindClass("java/lang/System");
        if (sys_cls && !env->ExceptionCheck()) {
            jmethodID set_prop = env->GetStaticMethodID(
                sys_cls, "setProperty", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
            if (set_prop && !env->ExceptionCheck()) {
                jstring jk = newJniStringSafe(env, "user.timezone");
                jstring jv = newJniStringSafe(env, cfg.timezone.c_str(), cfg.timezone.size());
                jobject prev = nullptr;
                if (jk && jv && !env->ExceptionCheck()) {
                    prev = env->CallStaticObjectMethod(sys_cls, set_prop, jk, jv);
                }
                clearJniException(env);
                if (prev) env->DeleteLocalRef(prev);
            }
        }
        clearJniException(env);
    }

    env->PopLocalFrame(nullptr);
    applyJavaLocaleOnly(env, cfg);
}

using FnNativeSetConfigV33 = void (*)(
    JNIEnv*, jclass, jlong, jint, jint, jstring,
    jint, jint, jint, jint, jint, jint, jint, jint, jint, jint, jint, jint, jint, jint, jint);
using FnNativeSetConfigV34 = void (*)(
    JNIEnv*, jclass, jlong, jint, jint, jstring, jobjectArray,
    jint, jint, jint, jint, jint, jint, jint, jint, jint, jint, jint, jint, jint, jint, jint, jint);

using FnLocaleNativeSetDefault = void (*)(JNIEnv*, jclass, jstring);

FnNativeSetConfigV33 g_orig_nativeSetConfig_v33 = nullptr;
FnNativeSetConfigV34 g_orig_nativeSetConfig_v34 = nullptr;
FnLocaleNativeSetDefault g_orig_locale_set_default = nullptr;

bool localeTagsEquivalent(const char* a, const char* b) {
    if (!a || !b) return false;
    while (*a != '\0' && *b != '\0') {
        char ca = (*a >= 'A' && *a <= 'Z') ? static_cast<char>(*a + ('a' - 'A')) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? static_cast<char>(*b + ('a' - 'A')) : *b;
        if (ca == '_') ca = '-';
        if (cb == '_') cb = '-';
        if (ca != cb) return false;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

void applyJavaCoreLocaleOnly(JNIEnv* env, const stealth::StealthConfig& cfg) {
    if (!env || !cfg.spoof_locale || cfg.locale.empty()) return;
    if (env->PushLocalFrame(8) != 0) {
        clearJniException(env);
        return;
    }
    jclass loc_cls = env->FindClass("java/util/Locale");
    if (loc_cls && !env->ExceptionCheck()) {
        jmethodID for_tag = env->GetStaticMethodID(loc_cls, "forLanguageTag", "(Ljava/lang/String;)Ljava/util/Locale;");
        jmethodID set_def = env->GetStaticMethodID(loc_cls, "setDefault", "(Ljava/util/Locale;)V");
        if (for_tag && set_def && !env->ExceptionCheck()) {
            jstring tag = newJniStringSafe(env, cfg.locale.c_str(), cfg.locale.size());
            if (tag) {
                jobject loc_obj = env->CallStaticObjectMethod(loc_cls, for_tag, tag);
                if (!env->ExceptionCheck() && loc_obj) {
                    env->CallStaticVoidMethod(loc_cls, set_def, loc_obj);
                }
            }
        }
    }
    clearJniException(env);
    env->PopLocalFrame(nullptr);
}

void hook_LocaleNative_setDefaultNative(JNIEnv* env, jclass clazz, jstring languageTag) {
    if (!g_cfg.spoof_locale || g_cfg.locale.empty()) {
        if (g_orig_locale_set_default) {
            g_orig_locale_set_default(env, clazz, languageTag);
        }
        return;
    }
    const pid_t self = gettid();
    if (__atomic_load_n(&g_locale_hook_tid, __ATOMIC_ACQUIRE) == self) {
        if (g_orig_locale_set_default) {
            g_orig_locale_set_default(env, clazz, languageTag);
        }
        return;
    }
    if (languageTag != nullptr && env) {
        const char* tag_utf = env->GetStringUTFChars(languageTag, nullptr);
        if (env->ExceptionCheck()) {
            clearJniException(env);
        }
        bool equiv = false;
        if (tag_utf != nullptr) {
            equiv = localeTagsEquivalent(tag_utf, g_cfg.locale.c_str());
            env->ReleaseStringUTFChars(languageTag, tag_utf);
        }
        if (equiv) {
            if (g_orig_locale_set_default) {
                g_orig_locale_set_default(env, clazz, languageTag);
            }
            return;
        }
    }
    pid_t expected = 0;
    if (__atomic_compare_exchange_n(&g_locale_hook_tid, &expected, self, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        applyJavaCoreLocaleOnly(env, g_cfg);
        __atomic_store_n(&g_locale_hook_tid, 0, __ATOMIC_RELEASE);
        return;
    }
    jstring spoofed = env ? newJniStringSafe(env, g_cfg.locale.c_str(), g_cfg.locale.size()) : nullptr;
    if (g_orig_locale_set_default) {
        g_orig_locale_set_default(env, clazz, spoofed ? spoofed : languageTag);
    }
    if (spoofed && env) {
        env->DeleteLocalRef(spoofed);
    }
}

void installLocaleNativeHook(zygisk::Api* api, JNIEnv* env) {
    if (!api || !env || !g_cfg.spoof_locale || g_cfg.locale.empty()) {
        return;
    }
    static constexpr const char* kLocaleSig = "(Ljava/lang/String;)V";
    const char* cls_name = "com/android/icu/util/LocaleNative";
    const char* method_name = "setDefaultNative";

    jclass cls = env->FindClass(cls_name);
    jmethodID mid = nullptr;
    if (cls && !env->ExceptionCheck()) {
        mid = env->GetStaticMethodID(cls, method_name, kLocaleSig);
    }
    if (!mid || env->ExceptionCheck()) {
        clearJniException(env);
        if (cls) {
            env->DeleteLocalRef(cls);
            cls = nullptr;
        }
        cls_name = "libcore/icu/ICU";
        method_name = "setDefaultLocale";
        cls = env->FindClass(cls_name);
        if (cls && !env->ExceptionCheck()) {
            mid = env->GetStaticMethodID(cls, method_name, kLocaleSig);
        }
    }
    if (mid && !env->ExceptionCheck()) {
        if (cls) {
            env->DeleteLocalRef(cls);
            cls = nullptr;
        }
        JNINativeMethod method = {
            method_name,
            kLocaleSig,
            reinterpret_cast<void*>(hook_LocaleNative_setDefaultNative),
        };
        api->hookJniNativeMethods(env, cls_name, &method, 1);
        g_orig_locale_set_default = reinterpret_cast<FnLocaleNativeSetDefault>(method.fnPtr);
        g_locale_jni_hooked = (g_orig_locale_set_default != nullptr);
    } else {
        clearJniException(env);
        if (cls) {
            env->DeleteLocalRef(cls);
        }
    }
}

void hook_nativeSetConfiguration_v33(
    JNIEnv* env, jclass clazz, jlong ptr, jint mcc, jint mnc, jstring locale,
    jint orientation, jint touchscreen, jint density, jint keyboard,
    jint keyboardHidden, jint navigation, jint screenWidth, jint screenHeight,
    jint smallestScreenWidthDp, jint screenWidthDp, jint screenHeightDp,
    jint screenLayout, jint uiMode, jint colorMode, jint majorVersion) {
    jint eff_mcc = (g_cfg.spoof_carrier && g_spoof_mcc > 0) ? g_spoof_mcc : mcc;
    jint eff_mnc = (g_cfg.spoof_carrier && g_spoof_mcc > 0) ? g_spoof_mnc : mnc;
    jstring spoofed_loc = nullptr;
    jstring eff_locale = locale;
    if (g_cfg.spoof_locale && !g_cfg.locale.empty()) {
        spoofed_loc = newJniStringSafe(env, g_cfg.locale.c_str(), g_cfg.locale.size());
        if (spoofed_loc) {
            eff_locale = spoofed_loc;
        }
    }
    if (g_orig_nativeSetConfig_v33) {
        g_orig_nativeSetConfig_v33(
            env, clazz, ptr, eff_mcc, eff_mnc, eff_locale,
            orientation, touchscreen, density, keyboard,
            keyboardHidden, navigation, screenWidth, screenHeight,
            smallestScreenWidthDp, screenWidthDp, screenHeightDp,
            screenLayout, uiMode, colorMode, majorVersion);
    }
    if (spoofed_loc) {
        env->DeleteLocalRef(spoofed_loc);
    }
    applyJavaLocaleOnly(env, g_cfg);
}

void hook_nativeSetConfiguration_v34(
    JNIEnv* env, jclass clazz, jlong ptr, jint mcc, jint mnc, jstring defaultLocale, jobjectArray locales,
    jint orientation, jint touchscreen, jint density, jint keyboard,
    jint keyboardHidden, jint navigation, jint screenWidth, jint screenHeight,
    jint smallestScreenWidthDp, jint screenWidthDp, jint screenHeightDp,
    jint screenLayout, jint uiMode, jint colorMode, jint grammaticalGender, jint majorVersion) {
    jint eff_mcc = (g_cfg.spoof_carrier && g_spoof_mcc > 0) ? g_spoof_mcc : mcc;
    jint eff_mnc = (g_cfg.spoof_carrier && g_spoof_mcc > 0) ? g_spoof_mnc : mnc;
    jstring spoofed_loc = nullptr;
    jstring eff_default = defaultLocale;
    jobjectArray spoofed_arr = nullptr;
    jobjectArray eff_locales = locales;
    if (g_cfg.spoof_locale && !g_cfg.locale.empty()) {
        spoofed_loc = newJniStringSafe(env, g_cfg.locale.c_str(), g_cfg.locale.size());
        if (spoofed_loc) {
            eff_default = spoofed_loc;
            if (locales != nullptr) {
                jclass str_cls = env->FindClass("java/lang/String");
                if (str_cls && !env->ExceptionCheck()) {
                    spoofed_arr = env->NewObjectArray(1, str_cls, spoofed_loc);
                    if (spoofed_arr && !env->ExceptionCheck()) {
                        eff_locales = spoofed_arr;
                    }
                    env->DeleteLocalRef(str_cls);
                }
                clearJniException(env);
            }
        }
    }
    if (g_orig_nativeSetConfig_v34) {
        g_orig_nativeSetConfig_v34(
            env, clazz, ptr, eff_mcc, eff_mnc, eff_default, eff_locales,
            orientation, touchscreen, density, keyboard,
            keyboardHidden, navigation, screenWidth, screenHeight,
            smallestScreenWidthDp, screenWidthDp, screenHeightDp,
            screenLayout, uiMode, colorMode, grammaticalGender, majorVersion);
    }
    if (spoofed_arr) env->DeleteLocalRef(spoofed_arr);
    if (spoofed_loc) env->DeleteLocalRef(spoofed_loc);
    applyJavaLocaleOnly(env, g_cfg);
}

void installAssetManagerConfigHook(zygisk::Api* api, JNIEnv* env) {
    if (!api || !env || (!g_cfg.spoof_locale && !g_cfg.spoof_carrier)) {
        return;
    }
    static constexpr const char* kSigV33 = "(JIILjava/lang/String;IIIIIIIIIIIIIII)V";
    static constexpr const char* kSigV34 = "(JIILjava/lang/String;[Ljava/lang/String;IIIIIIIIIIIIIIII)V";

    jclass am_cls = env->FindClass("android/content/res/AssetManager");
    if (!am_cls || env->ExceptionCheck()) {
        clearJniException(env);
        return;
    }
    jmethodID mid33 = env->GetStaticMethodID(am_cls, "nativeSetConfiguration", kSigV33);
    if (mid33 && !env->ExceptionCheck()) {
        JNINativeMethod method = {
            "nativeSetConfiguration",
            kSigV33,
            reinterpret_cast<void*>(hook_nativeSetConfiguration_v33),
        };
        api->hookJniNativeMethods(env, "android/content/res/AssetManager", &method, 1);
        g_orig_nativeSetConfig_v33 = reinterpret_cast<FnNativeSetConfigV33>(method.fnPtr);
        g_jni_hooked = (g_orig_nativeSetConfig_v33 != nullptr);
    } else {
        clearJniException(env);
        jmethodID mid34 = env->GetStaticMethodID(am_cls, "nativeSetConfiguration", kSigV34);
        if (mid34 && !env->ExceptionCheck()) {
            JNINativeMethod method = {
                "nativeSetConfiguration",
                kSigV34,
                reinterpret_cast<void*>(hook_nativeSetConfiguration_v34),
            };
            api->hookJniNativeMethods(env, "android/content/res/AssetManager", &method, 1);
            g_orig_nativeSetConfig_v34 = reinterpret_cast<FnNativeSetConfigV34>(method.fnPtr);
            g_jni_hooked = (g_orig_nativeSetConfig_v34 != nullptr);
        } else {
            clearJniException(env);
        }
    }
    env->DeleteLocalRef(am_cls);
}

class SandboxStealthModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        api_ = api;
        env_ = env;
    }

    void preServerSpecialize([[maybe_unused]] zygisk::ServerSpecializeArgs* args) override {
        if (!fetchConfigFromCompanion(api_, g_cfg_json, sizeof(g_cfg_json), g_cfg_json_len)) {
            g_cfg = stealth::StealthConfig{};
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        g_cfg = stealth::parseStealthConfig(g_cfg_json, g_cfg_json_len);
        if (!g_cfg.enabled) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        } else {
            LOGI("preServerSpecialize armed for sandbox user %d (oem=%s)", g_cfg.sandbox_user_id, stealth::kOemProfileName);
        }
    }

    void postServerSpecialize([[maybe_unused]] const zygisk::ServerSpecializeArgs* args) override {
        if (g_cfg.enabled) {
            injectDexAndInstallSystemHook(env_, "system_server");
        }
        api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        if (!args) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        const char* raw_name = nullptr;
        if (args->nice_name != nullptr) {
            raw_name = env_->GetStringUTFChars(args->nice_name, nullptr);
            if (!raw_name || env_->ExceptionCheck()) {
                clearJniException(env_);
                if (raw_name != nullptr) {
                    env_->ReleaseStringUTFChars(args->nice_name, raw_name);
                    raw_name = nullptr;
                }
            }
        }
        stealth::FixedStr<128> proc_name(raw_name ? raw_name : "");
        if (raw_name != nullptr) {
            env_->ReleaseStringUTFChars(args->nice_name, raw_name);
        }

        const int uid = static_cast<int>(args->uid);
        const int user_id = uid / stealth::kAndroidUserStride;
        const int app_id = uid % stealth::kAndroidUserStride;

        // 1. Phone service host process: inject ServiceManager wrapper only, never PLT hook.
        if (uid == 1001 && proc_name == "com.android.phone") {
            if (fetchConfigFromCompanion(api_, g_cfg_json, sizeof(g_cfg_json), g_cfg_json_len)) {
                g_cfg = stealth::parseStealthConfig(g_cfg_json, g_cfg_json_len);
                g_is_phone_proc = g_cfg.enabled;
            }
            if (!g_is_phone_proc) {
                api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            }
            return;
        }

        // 2. Fast zero-IPC exit for User 0, dual-clone user 999, and system UIDs (<10000); keep isolated processes (90000..99999) in scope.
        if (user_id <= 0 || user_id == stealth::kXSpaceUserId ||
            app_id < stealth::kFirstAppId || app_id >= stealth::kAndroidUserStride) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        // 3. Sandbox user process: verify against companion policy.
        if (!fetchConfigFromCompanion(api_, g_cfg_json, sizeof(g_cfg_json), g_cfg_json_len)) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        g_cfg = stealth::parseStealthConfig(g_cfg_json, g_cfg_json_len);
        if (!stealth::shouldSpoofAppUid(g_cfg, uid)) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        g_baked_props = stealth::bakeSpoofedProps(g_cfg);
        populateFakeProps(g_baked_props, g_fake_props);
        if (!stealth::parseMccMnc(g_cfg.sim_operator.c_str(), g_spoof_mcc, g_spoof_mnc)) {
            g_spoof_mcc = 0;
            g_spoof_mnc = 0;
        }

        g_is_sandbox_app = true;
        if (g_cfg.sanitize_network) {
            uint8_t octets[4] = {10, 172, 10, 2};
            if (!stealth::parseIPv4Octets(g_cfg.sandbox_link_ipv4, octets)) {
                octets[0] = 10;
                octets[1] = 172;
                octets[2] = 10;
                octets[3] = 2;
            }
            std::memcpy(&g_sandbox_ipv4_nbo, octets, sizeof(g_sandbox_ipv4_nbo));
        } else {
            g_sandbox_ipv4_nbo = 0;
        }
        if (g_cfg.spoof_timezone && !g_cfg.timezone.empty()) {
            // Bionic localtime() reads persist.sys.timezone directly inside libc.so (outside PLT hook scope)
            // unless overridden via TZ.
            setenv("TZ", g_cfg.timezone.c_str(), 1);
            tzset();
        }

        if (g_cfg.prop_hook_mode != "dlclose") {
            const bool want_props = g_cfg.spoof_carrier || g_cfg.spoof_timezone || g_cfg.spoof_locale ||
                g_cfg.spoof_device_region || g_cfg.hide_adb;
            const bool want_net = g_cfg.sanitize_network;
            const bool want_proc = g_cfg.enabled;
            TargetList prop_hits{};
            TargetList net_hits{};
            TargetList proc_hits{};
            findLibrariesFromMaps(want_props, prop_hits, want_net, net_hits, want_proc, proc_hits);

            bool has_registered = false;
            FnPropFind propFindHooks[kMaxPropHookSlots] = {};
            FnPropReadCb propCbHooks[kMaxPropHookSlots] = {};
            FnPropRead propReadHooks[kMaxPropHookSlots] = {};
            FnPropGet propGetHooks[kMaxPropHookSlots] = {};
            fillPropHookTables(propFindHooks, propCbHooks, propReadHooks, propGetHooks,
                               std::make_index_sequence<kMaxPropHookSlots>{});
            FnGetIfAddrs netHooks[kMaxNetHookSlots] = {};
            fillNetHookTable(netHooks, std::make_index_sequence<kMaxNetHookSlots>{});
            FnOpen openHooks[kMaxProcHookSlots] = {};
            FnOpen2 open2Hooks[kMaxProcHookSlots] = {};
            FnFopen fopenHooks[kMaxProcHookSlots] = {};
            fillProcHookTables(openHooks, open2Hooks, fopenHooks, std::make_index_sequence<kMaxProcHookSlots>{});

            size_t prop_libs_registered = prop_hits.count;
            for (size_t i = 0; i < prop_hits.count; i++) {
                const ResolvedTarget& pt = prop_hits.items[i];
                api_->pltHookRegister(pt.dev, pt.inode, "__system_property_find",
                                      reinterpret_cast<void*>(propFindHooks[i]),
                                      reinterpret_cast<void**>(&g_orig_prop_find[i]));
                api_->pltHookRegister(pt.dev, pt.inode, "__system_property_read_callback",
                                      reinterpret_cast<void*>(propCbHooks[i]),
                                      reinterpret_cast<void**>(&g_orig_prop_cb[i]));
                api_->pltHookRegister(pt.dev, pt.inode, "__system_property_read",
                                      reinterpret_cast<void*>(propReadHooks[i]),
                                      reinterpret_cast<void**>(&g_orig_prop_read[i]));
                api_->pltHookRegister(pt.dev, pt.inode, "__system_property_get",
                                      reinterpret_cast<void*>(propGetHooks[i]),
                                      reinterpret_cast<void**>(&g_orig_prop_get[i]));
                has_registered = true;
            }
            size_t net_libs_registered = net_hits.count;
            for (size_t i = 0; i < net_hits.count; i++) {
                const ResolvedTarget& nt = net_hits.items[i];
                api_->pltHookRegister(nt.dev, nt.inode, "getifaddrs",
                                      reinterpret_cast<void*>(netHooks[i]),
                                      reinterpret_cast<void**>(&g_orig_getifaddrs[i]));
                has_registered = true;
            }
            size_t proc_libs_registered = proc_hits.count;
            for (size_t i = 0; i < proc_hits.count; i++) {
                const ResolvedTarget& prt = proc_hits.items[i];
                api_->pltHookRegister(prt.dev, prt.inode, "open",
                                      reinterpret_cast<void*>(openHooks[i]),
                                      reinterpret_cast<void**>(&g_orig_open[i]));
                api_->pltHookRegister(prt.dev, prt.inode, "__open_2",
                                      reinterpret_cast<void*>(open2Hooks[i]),
                                      reinterpret_cast<void**>(&g_orig_open2[i]));
                api_->pltHookRegister(prt.dev, prt.inode, "fopen",
                                      reinterpret_cast<void*>(fopenHooks[i]),
                                      reinterpret_cast<void**>(&g_orig_fopen[i]));
                has_registered = true;
            }
            if (has_registered) {
                bool committed = api_->pltHookCommit();
                bool any_orig = false;
                for (size_t i = 0; i < prop_libs_registered; i++) {
                    if (g_orig_prop_find[i] || g_orig_prop_cb[i] || g_orig_prop_read[i] || g_orig_prop_get[i]) any_orig = true;
                }
                for (size_t i = 0; i < net_libs_registered; i++) {
                    if (g_orig_getifaddrs[i]) any_orig = true;
                }
                for (size_t i = 0; i < proc_libs_registered; i++) {
                    if (g_orig_open[i] || g_orig_open2[i] || g_orig_fopen[i]) any_orig = true;
                }
                g_plt_hooked = committed || any_orig;
                installAssetManagerConfigHook(api_, env_);
                installLocaleNativeHook(api_, env_);
                if (g_plt_hooked || g_jni_hooked || g_locale_jni_hooked) {
                    LOGI("pltHookCommit active for %s (%d) oem=%s committed=%d prop_libs=%zu net_libs=%zu proc_libs=%zu jni_cfg=%d jni_loc=%d",
                         proc_name.c_str(), uid, stealth::kOemProfileName, committed ? 1 : 0, prop_libs_registered, net_libs_registered, proc_libs_registered, g_jni_hooked ? 1 : 0, g_locale_jni_hooked ? 1 : 0);
                } else {
                    LOGW("pltHookCommit failed in %s (%d)", proc_name.c_str(), uid);
                }
            }
        }
    }

    void postAppSpecialize([[maybe_unused]] const zygisk::AppSpecializeArgs* args) override {
        if (g_is_phone_proc) {
            injectDexAndInstallSystemHook(env_, "com.android.phone");
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        if (g_is_sandbox_app) {
            applyJavaTimezoneAndLocale(env_, g_cfg);
        }

        if (!g_plt_hooked && !g_jni_hooked && !g_locale_jni_hooked) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }
    }

private:
    zygisk::Api* api_ = nullptr;
    JNIEnv* env_ = nullptr;
};

} // namespace

REGISTER_ZYGISK_MODULE(SandboxStealthModule)
REGISTER_ZYGISK_COMPANION(companionHandler)
