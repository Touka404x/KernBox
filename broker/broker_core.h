#ifndef KERNBOX_BROKER_CORE_H
#define KERNBOX_BROKER_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BROKER_MAX_RPC_LINE_BYTES   8192
#define BROKER_MAX_RPC_RESP_BYTES   65536
#define BROKER_MAX_AUTH_FILE_BYTES  1024
#define BROKER_MAX_ID_BYTES         128
#define BROKER_MAX_PKG_BYTES        255
#define BROKER_MAX_ACTIVITY_BYTES   255
#define BROKER_MAX_APK_PATHS        32
#define BROKER_MAX_APK_PATH_BYTES   512

#define BROKER_MIN_APP_ID           10000
#define BROKER_ANDROID_USER_WIDTH   100000

#define BROKER_SELINUX_CTX          "u:r:sandbox_broker:s0"
#define BROKER_SOCK_DIR             "/dev/socket/sandbox_ctrl"
#define BROKER_SOCK_PATH            "/dev/socket/sandbox_ctrl/ctrl.sock"
#define BROKER_PRIV_DIR             "/dev/socket/sandbox_priv"
#define BROKER_GUARD_SOCK_PATH      "/dev/socket/sandbox_priv/guard.sock"
#define BROKER_AUTH_PATH            "/dev/socket/sandbox_priv/broker_auth.json"
#define BROKER_PROC_ATTR_CURRENT    "/proc/self/attr/current"

typedef struct broker_req_info {
    char id[BROKER_MAX_ID_BYTES + 1];
    size_t trimmed_off;
    size_t trimmed_len;
    int is_install_apk;
} broker_req_info_t;

/*
 * Verifies /proc/self/attr/current content matches u:r:sandbox_broker:s0
 * after stripping trailing NUL bytes and ASCII whitespace.
 * Returns 0 on match, -1 on mismatch.
 */
int broker_check_self_context(const char *raw, size_t len);

/*
 * Strictly parses broker_auth.json (`{"allowed_user0_uid":<int>}`).
 * Rejects unknown keys, duplicate keys, non-integer values, and trailing data.
 * Returns 0 on success and stores UID in *out_uid, -1 on error.
 */
int broker_parse_auth_json(const char *raw, size_t len, int *out_uid);

/*
 * Validates SO_PEERCRED UID + SO_PEERSEC context against allowed_user0_uid.
 * Allows u:r:untrusted_app* in User 0 only; rejects isolated_app and work UIDs.
 * Returns 0 if authorized, -1 otherwise.
 */
int broker_authorize_peer(int peer_uid, const char *sec_ctx, size_t sec_len, int allowed_user0_uid);

/*
 * Enforces the frozen max-8192B newline-JSON RPC schema, op whitelist,
 * package/activity/apk_paths regex/path safety, and config override values.
 * Returns 0 on success (populating out), or -1 on error (writing errbuf).
 */
int broker_validate_rpc_request(
    const char *line,
    size_t len,
    broker_req_info_t *out,
    char *errbuf,
    size_t errcap);

/*
 * Formats `{"id":"...","ok":false,"error":"...","data":{}}\n` into out.
 * Always writes valid JSON terminated by '\n' + '\0' when outcap >= 64.
 * Returns number of payload bytes (excluding terminating NUL).
 */
size_t broker_format_error_json(const char *id, const char *msg, char *out, size_t outcap);

#ifdef __cplusplus
}
#endif

#endif /* KERNBOX_BROKER_CORE_H */
