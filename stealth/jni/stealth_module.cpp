#include <sys/types.h>
#include "zygisk.hpp"
#include "stealth_logic.hpp"
#include "stealth_agent_dex.h"

#include <android/log.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <ifaddrs.h>
#include <link.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "SandboxStealth", __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, "SandboxStealth", __VA_ARGS__)

namespace {

constexpr const char* kStealthConfigPath = "/data/adb/sandbox_guard/stealth.json";
constexpr const char* kZygiskDisabledFlag = "/data/adb/modules/sandbox_guard/zygisk_disabled";
constexpr const char* kDisabledJson = "{\"enabled\":false}";
constexpr size_t kMaxConfigBytes = 16384;

stealth::StealthConfig g_cfg;
stealth::BakedProps g_baked_props;
std::string g_cfg_json;
bool g_is_phone_proc = false;
bool g_is_sandbox_app = false;
bool g_plt_hooked = false;
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

constexpr size_t kPropSuffixCount = 4;
const char* const kPropTargetSuffixes[kPropSuffixCount] = {
    "/libandroid_runtime.so",
    "/libbase.so",
    "/libcutils.so",
    "/libutils.so",
};
constexpr size_t kNetSuffixCount = 1;
const char* const kNetTargetSuffixes[kNetSuffixCount] = {
    "/libjavacore.so",
};
constexpr size_t kMaxPropHookSlots = 12;
constexpr size_t kMaxNetHookSlots = 2;

using FnGetIfAddrs = int (*)(struct ifaddrs** ifap);
using FnPropFind = const prop_info* (*)(const char* name);
using FnPropReadCb = void (*)(
    const prop_info* pi,
    void (*callback)(void* cookie, const char* name, const char* value, uint32_t serial),
    void* cookie);
using FnPropGet = int (*)(const char* name, char* value);

FnGetIfAddrs g_orig_getifaddrs[kMaxNetHookSlots] = {};
FnPropFind g_orig_prop_find[kMaxPropHookSlots] = {};
FnPropReadCb g_orig_prop_cb[kMaxPropHookSlots] = {};
FnPropGet g_orig_prop_get[kMaxPropHookSlots] = {};

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
        if (cur->ifa_name && std::strncmp(cur->ifa_name, "tun", 3) == 0) {
            // Coalesce tun* into "lo" with null addrs so NetworkInterface skips it while freeifaddrs() frees cleanly.
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
        if (fam == AF_INET6) {
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
    if (idx >= 0 && g_baked_props.active[idx] && (idx == 0 || idx >= 7)) {
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

int hookPropGetImpl(FnPropGet orig, const char* name, char* value) {
    if (!name || !value) {
        return orig ? orig(name, value) : 0;
    }
    const int idx = stealth::spoofablePropIndex(name);
    if (idx >= 0 && g_baked_props.active[idx]) {
        if (idx >= 1 && idx <= 6) {
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

std::string readSafeRootConfig() {
    if (access(kZygiskDisabledFlag, F_OK) == 0) {
        return kDisabledJson;
    }
    int fd = open(kStealthConfigPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return kDisabledJson;
    }
    struct stat st{};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        st.st_size <= 0 || static_cast<size_t>(st.st_size) > kMaxConfigBytes) {
        close(fd);
        return kDisabledJson;
    }
    std::string out(static_cast<size_t>(st.st_size), '\0');
    size_t total = 0;
    while (total < out.size()) {
        ssize_t r = read(fd, &out[total], out.size() - total);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return kDisabledJson;
        }
        if (r == 0) break;
        total += static_cast<size_t>(r);
    }
    close(fd);
    out.resize(total);
    return out.empty() ? kDisabledJson : out;
}

void companionHandler(int client_fd) {
    std::string json = readSafeRootConfig();
    if (json.size() > kMaxConfigBytes) {
        json = kDisabledJson;
    }
    uint32_t len = static_cast<uint32_t>(json.size());
    if (writeExact(client_fd, &len, sizeof(len))) {
        (void)writeExact(client_fd, json.data(), json.size());
    }
    close(client_fd);
}

bool fetchConfigFromCompanion(zygisk::Api* api, std::string& out_json) {
    int fd = api->connectCompanion();
    if (fd < 0) {
        return false;
    }
    uint32_t len = 0;
    if (!readExact(fd, &len, sizeof(len)) || len == 0 || len > kMaxConfigBytes) {
        close(fd);
        return false;
    }
    out_json.resize(len);
    bool ok = readExact(fd, &out_json[0], len);
    close(fd);
    if (!ok) {
        out_json.clear();
    }
    return ok;
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

struct PhdrMultiCtx {
    TargetList* prop_list;
    bool want_props;
    TargetList* net_list;
    bool want_net;
};

int phdrMultiMatchCallback(struct dl_phdr_info* info, [[maybe_unused]] size_t size, void* raw_ctx) {
    auto* ctx = static_cast<PhdrMultiCtx*>(raw_ctx);
    if (!info || !info->dlpi_name || info->dlpi_name[0] != '/') {
        return 0;
    }
    const size_t plen = std::strlen(info->dlpi_name);
    const bool match_prop = ctx->want_props && ctx->prop_list->count < ctx->prop_list->cap &&
        endsWithAnySuffix(info->dlpi_name, plen, kPropTargetSuffixes, kPropSuffixCount);
    const bool match_net = ctx->want_net && ctx->net_list->count < ctx->net_list->cap &&
        endsWithAnySuffix(info->dlpi_name, plen, kNetTargetSuffixes, kNetSuffixCount);
    if (!match_prop && !match_net) {
        return 0;
    }
    struct stat st{};
    if (stat(info->dlpi_name, &st) == 0 && S_ISREG(st.st_mode)) {
        if (match_prop) appendUniqueTarget(*ctx->prop_list, st.st_dev, st.st_ino);
        if (match_net) appendUniqueTarget(*ctx->net_list, st.st_dev, st.st_ino);
    }
    const bool props_full = !ctx->want_props || ctx->prop_list->count >= ctx->prop_list->cap;
    const bool net_full = !ctx->want_net || ctx->net_list->count >= ctx->net_list->cap;
    return (props_full && net_full) ? 1 : 0;
}

// Single-pass /proc/self/maps resolution collects up to kMaxPropHookSlots unique (dev, ino)
// prop library mappings (handling APEX + system namespace duplicates like libbase.so).
void findLibrariesFromMaps(bool want_props, TargetList& prop_list, bool want_net, TargetList& net_list) {
    prop_list.count = 0;
    prop_list.cap = kMaxPropHookSlots;
    net_list.count = 0;
    net_list.cap = kMaxNetHookSlots;
    if (!want_props && !want_net) return;

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
                if (want_props && prop_list.count < prop_list.cap &&
                    endsWithAnySuffix(path, plen, kPropTargetSuffixes, kPropSuffixCount)) {
                    appendUniqueTarget(prop_list, dev, ino);
                }
                if (want_net && net_list.count < net_list.cap &&
                    endsWithAnySuffix(path, plen, kNetTargetSuffixes, kNetSuffixCount)) {
                    appendUniqueTarget(net_list, dev, ino);
                }
                const bool props_full = !want_props || prop_list.count >= prop_list.cap;
                const bool net_full = !want_net || net_list.count >= net_list.cap;
                if (props_full && net_full) {
                    break;
                }
            }
        }
        std::fclose(fp);
    }

    if ((want_props && prop_list.count == 0) || (want_net && net_list.count == 0)) {
        PhdrMultiCtx ctx{&prop_list, want_props, &net_list, want_net};
        dl_iterate_phdr(phdrMultiMatchCallback, &ctx);
    }
}

void clearJniException(JNIEnv* env) {
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
}

void injectDexAndInstallSystemHook(JNIEnv* env, const char* process_name) {
    if (!env || g_cfg_json.empty()) return;
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

    jclass bb_cls = env->FindClass("java/nio/ByteBuffer");
    if (!bb_cls) { clearJniException(env); env->PopLocalFrame(nullptr); return; }
    jmethodID wrap_mid = env->GetStaticMethodID(bb_cls, "wrap", "([B)Ljava/nio/ByteBuffer;");
    if (!wrap_mid) { clearJniException(env); env->PopLocalFrame(nullptr); return; }
    jobject dex_buf = env->CallStaticObjectMethod(bb_cls, wrap_mid, dex_bytes);
    if (env->ExceptionCheck() || !dex_buf) { clearJniException(env); env->PopLocalFrame(nullptr); return; }

    jclass loader_cls = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (!loader_cls) { clearJniException(env); env->PopLocalFrame(nullptr); return; }
    jmethodID ctor_mid = env->GetMethodID(loader_cls, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (!ctor_mid) { clearJniException(env); env->PopLocalFrame(nullptr); return; }
    jobject mem_cl = env->NewObject(loader_cls, ctor_mid, dex_buf, parent_cl);
    if (env->ExceptionCheck() || !mem_cl) { clearJniException(env); env->PopLocalFrame(nullptr); return; }

    jmethodID load_mid = env->GetMethodID(cl_cls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (!load_mid) { clearJniException(env); env->PopLocalFrame(nullptr); return; }
    jstring hook_name = env->NewStringUTF("com.sandbox.stealth.SystemServerHook");
    auto hook_cls = static_cast<jclass>(env->CallObjectMethod(mem_cl, load_mid, hook_name));
    if (env->ExceptionCheck() || !hook_cls) { clearJniException(env); env->PopLocalFrame(nullptr); return; }

    jmethodID install_mid = env->GetStaticMethodID(
        hook_cls, "install", "(Ljava/lang/String;Ljava/lang/String;)Z");
    if (!install_mid) { clearJniException(env); env->PopLocalFrame(nullptr); return; }

    jstring json_str = env->NewStringUTF(g_cfg_json.c_str());
    jstring proc_str = env->NewStringUTF(process_name);
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

void applyJavaTimezoneAndLocale(JNIEnv* env, const stealth::StealthConfig& cfg) {
    if (!env) return;
    if (env->PushLocalFrame(16) != 0) {
        clearJniException(env);
        return;
    }

    if (cfg.spoof_timezone && !cfg.timezone.empty()) {
        jclass tz_cls = env->FindClass("java/util/TimeZone");
        if (tz_cls) {
            jmethodID get_tz = env->GetStaticMethodID(tz_cls, "getTimeZone", "(Ljava/lang/String;)Ljava/util/TimeZone;");
            jmethodID set_tz = env->GetStaticMethodID(tz_cls, "setDefault", "(Ljava/util/TimeZone;)V");
            if (get_tz && set_tz) {
                jstring tz_id = env->NewStringUTF(cfg.timezone.c_str());
                jobject tz_obj = env->CallStaticObjectMethod(tz_cls, get_tz, tz_id);
                if (!env->ExceptionCheck() && tz_obj) {
                    env->CallStaticVoidMethod(tz_cls, set_tz, tz_obj);
                }
            }
        }
        clearJniException(env);
    }

    if (cfg.spoof_locale && !cfg.locale.empty()) {
        jclass loc_cls = env->FindClass("java/util/Locale");
        if (loc_cls) {
            jmethodID for_tag = env->GetStaticMethodID(loc_cls, "forLanguageTag", "(Ljava/lang/String;)Ljava/util/Locale;");
            jmethodID set_def = env->GetStaticMethodID(loc_cls, "setDefault", "(Ljava/util/Locale;)V");
            if (for_tag && set_def) {
                jstring tag = env->NewStringUTF(cfg.locale.c_str());
                jobject loc_obj = env->CallStaticObjectMethod(loc_cls, for_tag, tag);
                if (!env->ExceptionCheck() && loc_obj) {
                    env->CallStaticVoidMethod(loc_cls, set_def, loc_obj);
                }
            }
        }
        clearJniException(env);

        jclass ll_cls = env->FindClass("android/os/LocaleList");
        if (ll_cls) {
            jmethodID for_tags = env->GetStaticMethodID(ll_cls, "forLanguageTags", "(Ljava/lang/String;)Landroid/os/LocaleList;");
            jmethodID set_ll = env->GetStaticMethodID(ll_cls, "setDefault", "(Landroid/os/LocaleList;)V");
            if (for_tags && set_ll) {
                jstring tags = env->NewStringUTF(cfg.locale.c_str());
                jobject ll_obj = env->CallStaticObjectMethod(ll_cls, for_tags, tags);
                if (!env->ExceptionCheck() && ll_obj) {
                    env->CallStaticVoidMethod(ll_cls, set_ll, ll_obj);
                }
            }
        }
        clearJniException(env);

        // Clear stale Zygote pre-fork user.language/country/region system properties.
        std::string lang;
        std::string country;
        stealth::detail::splitLocaleTag(cfg.locale, cfg.device_region, lang, country);
        jclass sys_cls = env->FindClass("java/lang/System");
        if (sys_cls) {
            jmethodID set_prop = env->GetStaticMethodID(
                sys_cls, "setProperty", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
            if (set_prop) {
                auto setSysProp = [&](const char* k, const std::string& v) {
                    if (v.empty()) return;
                    jstring jk = env->NewStringUTF(k);
                    jstring jv = env->NewStringUTF(v.c_str());
                    jobject prev = env->CallStaticObjectMethod(sys_cls, set_prop, jk, jv);
                    if (prev) env->DeleteLocalRef(prev);
                    if (jk) env->DeleteLocalRef(jk);
                    if (jv) env->DeleteLocalRef(jv);
                };
                setSysProp("user.language", lang);
                setSysProp("user.country", country);
                setSysProp("user.region", country);
            }
        }
        clearJniException(env);
    }
    env->PopLocalFrame(nullptr);
}

class SandboxStealthModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        api_ = api;
        env_ = env;
    }

    void preServerSpecialize([[maybe_unused]] zygisk::ServerSpecializeArgs* args) override {
        if (!fetchConfigFromCompanion(api_, g_cfg_json)) {
            g_cfg = stealth::StealthConfig{};
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        g_cfg = stealth::parseStealthConfig(g_cfg_json);
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
        }
        std::string proc_name = raw_name ? raw_name : "";
        if (raw_name != nullptr) {
            env_->ReleaseStringUTFChars(args->nice_name, raw_name);
        }

        const int uid = static_cast<int>(args->uid);
        const int user_id = uid / stealth::kAndroidUserStride;
        const int app_id = uid % stealth::kAndroidUserStride;

        // 1. Phone service host process: inject ServiceManager wrapper only, never PLT hook.
        if (uid == 1001 && proc_name == "com.android.phone") {
            if (fetchConfigFromCompanion(api_, g_cfg_json)) {
                g_cfg = stealth::parseStealthConfig(g_cfg_json);
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
        if (!fetchConfigFromCompanion(api_, g_cfg_json)) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        g_cfg = stealth::parseStealthConfig(g_cfg_json);
        if (!stealth::shouldSpoofAppUid(g_cfg, uid)) {
            api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }
        g_baked_props = stealth::bakeSpoofedProps(g_cfg);
        populateFakeProps(g_baked_props, g_fake_props);

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
            const bool want_props = g_cfg.spoof_carrier || g_cfg.spoof_timezone || g_cfg.spoof_locale || g_cfg.spoof_device_region;
            const bool want_net = g_cfg.sanitize_network;
            TargetList prop_hits{};
            TargetList net_hits{};
            findLibrariesFromMaps(want_props, prop_hits, want_net, net_hits);

            bool has_registered = false;
            FnPropFind propFindHooks[kMaxPropHookSlots] = {
                hook_prop_find_slot<0>, hook_prop_find_slot<1>, hook_prop_find_slot<2>, hook_prop_find_slot<3>,
                hook_prop_find_slot<4>, hook_prop_find_slot<5>, hook_prop_find_slot<6>, hook_prop_find_slot<7>,
                hook_prop_find_slot<8>, hook_prop_find_slot<9>, hook_prop_find_slot<10>, hook_prop_find_slot<11>,
            };
            FnPropReadCb propCbHooks[kMaxPropHookSlots] = {
                hook_prop_read_cb_slot<0>, hook_prop_read_cb_slot<1>, hook_prop_read_cb_slot<2>, hook_prop_read_cb_slot<3>,
                hook_prop_read_cb_slot<4>, hook_prop_read_cb_slot<5>, hook_prop_read_cb_slot<6>, hook_prop_read_cb_slot<7>,
                hook_prop_read_cb_slot<8>, hook_prop_read_cb_slot<9>, hook_prop_read_cb_slot<10>, hook_prop_read_cb_slot<11>,
            };
            FnPropGet propGetHooks[kMaxPropHookSlots] = {
                hook_prop_get_slot<0>, hook_prop_get_slot<1>, hook_prop_get_slot<2>, hook_prop_get_slot<3>,
                hook_prop_get_slot<4>, hook_prop_get_slot<5>, hook_prop_get_slot<6>, hook_prop_get_slot<7>,
                hook_prop_get_slot<8>, hook_prop_get_slot<9>, hook_prop_get_slot<10>, hook_prop_get_slot<11>,
            };
            FnGetIfAddrs netHooks[kMaxNetHookSlots] = {
                hook_getifaddrs_slot<0>, hook_getifaddrs_slot<1>,
            };

            size_t prop_libs_registered = prop_hits.count;
            for (size_t i = 0; i < prop_hits.count; i++) {
                const ResolvedTarget& pt = prop_hits.items[i];
                api_->pltHookRegister(pt.dev, pt.inode, "__system_property_find",
                                      reinterpret_cast<void*>(propFindHooks[i]),
                                      reinterpret_cast<void**>(&g_orig_prop_find[i]));
                api_->pltHookRegister(pt.dev, pt.inode, "__system_property_read_callback",
                                      reinterpret_cast<void*>(propCbHooks[i]),
                                      reinterpret_cast<void**>(&g_orig_prop_cb[i]));
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
            if (has_registered) {
                bool committed = api_->pltHookCommit();
                bool any_orig = false;
                for (size_t i = 0; i < prop_libs_registered; i++) {
                    if (g_orig_prop_find[i] || g_orig_prop_cb[i] || g_orig_prop_get[i]) any_orig = true;
                }
                for (size_t i = 0; i < net_libs_registered; i++) {
                    if (g_orig_getifaddrs[i]) any_orig = true;
                }
                g_plt_hooked = committed || any_orig;
                if (g_plt_hooked) {
                    LOGI("pltHookCommit active for %s (%d) oem=%s committed=%d prop_libs=%zu net_libs=%zu",
                         proc_name.c_str(), uid, stealth::kOemProfileName, committed ? 1 : 0, prop_libs_registered, net_libs_registered);
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

        if (!g_plt_hooked) {
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
