#include "broker_core.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int is_ascii_ws(unsigned char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int is_alpha(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int is_alnum_underscore(unsigned char c) {
    return is_alpha(c) || (c >= '0' && c <= '9') || c == '_';
}

static int hex_val(unsigned char c) {
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'a' && c <= 'f') return (int)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (int)(c - 'A' + 10);
    return -1;
}

static void set_err(char *errbuf, size_t errcap, const char *fmt, ...) {
    if (!errbuf || errcap == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(errbuf, errcap, fmt, ap);
    va_end(ap);
    errbuf[errcap - 1] = '\0';
}

int broker_check_self_context(const char *raw, size_t len) {
    if (!raw) {
        return -1;
    }
    while (len > 0 && (raw[len - 1] == '\0' || is_ascii_ws((unsigned char)raw[len - 1]))) {
        len--;
    }
    size_t off = 0;
    while (off < len && is_ascii_ws((unsigned char)raw[off])) {
        off++;
    }
    size_t want = strlen(BROKER_SELINUX_CTX);
    if (len - off != want) {
        return -1;
    }
    return memcmp(raw + off, BROKER_SELINUX_CTX, want) == 0 ? 0 : -1;
}

int broker_authorize_peer(int peer_uid, const char *sec_ctx, size_t sec_len, int allowed_user0_uid) {
    if (allowed_user0_uid < BROKER_MIN_APP_ID || allowed_user0_uid >= BROKER_ANDROID_USER_WIDTH) {
        return -1;
    }
    if (peer_uid != allowed_user0_uid || peer_uid < BROKER_MIN_APP_ID || peer_uid >= BROKER_ANDROID_USER_WIDTH) {
        return -1;
    }
    if (!sec_ctx || sec_len == 0) {
        return -1;
    }

    size_t n = sec_len;
    if (n > 511) {
        n = 511;
    }
    /* Kernel SO_PEERSEC strings may carry trailing NUL padding. */
    while (n > 0 && (sec_ctx[n - 1] == '\0' || is_ascii_ws((unsigned char)sec_ctx[n - 1]))) {
        n--;
    }
    size_t off = 0;
    while (off < n && is_ascii_ws((unsigned char)sec_ctx[off])) {
        off++;
    }
    if (n <= off) {
        return -1;
    }

    char buf[512];
    size_t blen = n - off;
    memcpy(buf, sec_ctx + off, blen);
    buf[blen] = '\0';

    /* Reject any embedded NUL or isolated_app substring. */
    if (strlen(buf) != blen) {
        return -1;
    }
    if (strstr(buf, "isolated_app") != NULL) {
        return -1;
    }

    /* Require SELinux context "u:r:untrusted_app*..." */
    char *c1 = strchr(buf, ':');
    if (!c1 || (size_t)(c1 - buf) != 1 || buf[0] != 'u') {
        return -1;
    }
    char *p2 = c1 + 1;
    char *c2 = strchr(p2, ':');
    if (!c2 || (size_t)(c2 - p2) != 1 || p2[0] != 'r') {
        return -1;
    }
    char *dom = c2 + 1;
    const char *prefix = "untrusted_app";
    size_t plen = strlen(prefix);
    return strncmp(dom, prefix, plen) == 0 ? 0 : -1;
}

typedef struct json_cursor {
    const char *buf;
    size_t len;
    size_t pos;
    int depth;
} json_cursor_t;

static void jskip_ws(json_cursor_t *c) {
    while (c->pos < c->len && is_ascii_ws((unsigned char)c->buf[c->pos])) {
        c->pos++;
    }
}

static size_t append_utf8(char *out, size_t cap, size_t idx, uint32_t cp, int *has_nul) {
    if (cp == 0) {
        *has_nul = 1;
        return idx;
    }
    if (cp <= 0x7Fu) {
        if (idx < cap) out[idx] = (char)cp;
        return idx + 1;
    }
    if (cp <= 0x7FFu) {
        if (idx + 1 < cap) {
            out[idx] = (char)(0xC0u | (cp >> 6));
            out[idx + 1] = (char)(0x80u | (cp & 0x3Fu));
        }
        return idx + 2;
    }
    if (cp <= 0xFFFFu) {
        if (idx + 2 < cap) {
            out[idx] = (char)(0xE0u | (cp >> 12));
            out[idx + 1] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
            out[idx + 2] = (char)(0x80u | (cp & 0x3Fu));
        }
        return idx + 3;
    }
    if (idx + 3 < cap) {
        out[idx] = (char)(0xF0u | (cp >> 18));
        out[idx + 1] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
        out[idx + 2] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
        out[idx + 3] = (char)(0x80u | (cp & 0x3Fu));
    }
    return idx + 4;
}

static int jparse_hex4(json_cursor_t *c, uint32_t *out) {
    if (c->pos + 4 > c->len) {
        return -1;
    }
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        int d = hex_val((unsigned char)c->buf[c->pos + (size_t)i]);
        if (d < 0) {
            return -1;
        }
        v = (v << 4) | (uint32_t)d;
    }
    c->pos += 4;
    *out = v;
    return 0;
}

/*
 * Parses a JSON string token into out (if out != NULL and fits in cap - 1).
 * Sets *out_len to decoded byte length and *out_has_nul if '\u0000' was decoded.
 * Returns 0 on valid JSON string, -1 on syntax/control error.
 */
static int jparse_string(json_cursor_t *c, char *out, size_t cap, size_t *out_len, int *out_has_nul) {
    jskip_ws(c);
    if (c->pos >= c->len || c->buf[c->pos] != '"') {
        return -1;
    }
    c->pos++;
    size_t dlen = 0;
    int nul = 0;
    while (c->pos < c->len) {
        unsigned char ch = (unsigned char)c->buf[c->pos++];
        if (ch == '"') {
            if (out && cap > 0) {
                size_t term = dlen < cap - 1 ? dlen : cap - 1;
                out[term] = '\0';
            }
            if (out_len) *out_len = dlen;
            if (out_has_nul) *out_has_nul = nul;
            return 0;
        }
        if (ch < 0x20u) {
            return -1;
        }
        if (ch != '\\') {
            if (out && dlen + 1 < cap) {
                out[dlen] = (char)ch;
            }
            dlen++;
            continue;
        }
        if (c->pos >= c->len) {
            return -1;
        }
        unsigned char esc = (unsigned char)c->buf[c->pos++];
        unsigned char mapped = 0;
        switch (esc) {
            case '"': mapped = '"'; break;
            case '\\': mapped = '\\'; break;
            case '/': mapped = '/'; break;
            case 'b': mapped = '\b'; break;
            case 'f': mapped = '\f'; break;
            case 'n': mapped = '\n'; break;
            case 'r': mapped = '\r'; break;
            case 't': mapped = '\t'; break;
            case 'u': {
                uint32_t cp = 0;
                if (jparse_hex4(c, &cp) != 0) {
                    return -1;
                }
                if (cp >= 0xD800u && cp <= 0xDBFFu) {
                    if (c->pos + 2 <= c->len && c->buf[c->pos] == '\\' && c->buf[c->pos + 1] == 'u') {
                        c->pos += 2;
                        uint32_t low = 0;
                        if (jparse_hex4(c, &low) != 0 || low < 0xDC00u || low > 0xDFFFu) {
                            return -1;
                        }
                        cp = 0x10000u + (((cp - 0xD800u) << 10) | (low - 0xDC00u));
                    } else {
                        cp = 0xFFFDu;
                    }
                } else if (cp >= 0xDC00u && cp <= 0xDFFFu) {
                    cp = 0xFFFDu;
                }
                dlen = append_utf8(out, cap > 0 ? cap - 1 : 0, dlen, cp, &nul);
                continue;
            }
            default:
                return -1;
        }
        if (out && dlen + 1 < cap) {
            out[dlen] = (char)mapped;
        }
        dlen++;
    }
    return -1;
}

static int jconsume_char(json_cursor_t *c, char ch) {
    jskip_ws(c);
    if (c->pos >= c->len || c->buf[c->pos] != ch) {
        return -1;
    }
    c->pos++;
    return 0;
}

static int jconsume_null(json_cursor_t *c) {
    jskip_ws(c);
    if (c->pos + 4 <= c->len && memcmp(c->buf + c->pos, "null", 4) == 0) {
        c->pos += 4;
        return 0;
    }
    return -1;
}

static int jparse_int_strict(json_cursor_t *c, int *out_val) {
    jskip_ws(c);
    if (c->pos >= c->len) {
        return -1;
    }
    size_t start = c->pos;
    int neg = 0;
    if (c->buf[c->pos] == '-') {
        neg = 1;
        c->pos++;
        if (c->pos >= c->len) {
            return -1;
        }
    }
    if (c->buf[c->pos] == '0') {
        c->pos++;
        if (c->pos < c->len && (unsigned char)c->buf[c->pos] >= '0' && (unsigned char)c->buf[c->pos] <= '9') {
            return -1; /* Leading zeros are invalid JSON. */
        }
    } else if ((unsigned char)c->buf[c->pos] >= '1' && (unsigned char)c->buf[c->pos] <= '9') {
        while (c->pos < c->len && (unsigned char)c->buf[c->pos] >= '0' && (unsigned char)c->buf[c->pos] <= '9') {
            c->pos++;
        }
    } else {
        return -1;
    }
    if (c->pos < c->len && (c->buf[c->pos] == '.' || c->buf[c->pos] == 'e' || c->buf[c->pos] == 'E')) {
        return -1;
    }
    long long acc = 0;
    size_t i = neg ? start + 1 : start;
    for (; i < c->pos; i++) {
        acc = acc * 10 + (c->buf[i] - '0');
        if (acc > INT_MAX) {
            return -1;
        }
    }
    *out_val = neg ? (int)(-acc) : (int)acc;
    return 0;
}

int broker_parse_auth_json(const char *raw, size_t len, int *out_uid) {
    if (!raw || !out_uid || len == 0 || len > BROKER_MAX_AUTH_FILE_BYTES) {
        return -1;
    }
    json_cursor_t c = {raw, len, 0, 0};
    if (jconsume_char(&c, '{') != 0) {
        return -1;
    }
    jskip_ws(&c);
    int seen_uid = 0;
    int uid_val = 0;
    if (c.pos < c.len && c.buf[c.pos] == '}') {
        c.pos++;
    } else {
        for (;;) {
            char key[64];
            size_t klen = 0;
            int knul = 0;
            if (jparse_string(&c, key, sizeof(key), &klen, &knul) != 0 || knul) {
                return -1;
            }
            if (klen != strlen("allowed_user0_uid") || strcmp(key, "allowed_user0_uid") != 0) {
                return -1;
            }
            if (seen_uid) {
                return -1;
            }
            seen_uid = 1;
            if (jconsume_char(&c, ':') != 0) {
                return -1;
            }
            if (jparse_int_strict(&c, &uid_val) != 0 || uid_val < 0) {
                return -1;
            }
            jskip_ws(&c);
            if (c.pos < c.len && c.buf[c.pos] == ',') {
                c.pos++;
                continue;
            }
            if (jconsume_char(&c, '}') == 0) {
                break;
            }
            return -1;
        }
    }
    jskip_ws(&c);
    if (c.pos != c.len || !seen_uid) {
        return -1;
    }
    *out_uid = uid_val;
    return 0;
}

static int valid_package_name(const char *pkg, size_t len) {
    if (!pkg || len < 3 || len > BROKER_MAX_PKG_BYTES) {
        return 0;
    }
    if (!is_alpha((unsigned char)pkg[0])) {
        return 0;
    }
    int dots = 0;
    size_t seg_len = 1;
    for (size_t i = 1; i < len; i++) {
        unsigned char c = (unsigned char)pkg[i];
        if (c == '.') {
            if (seg_len == 0) {
                return 0;
            }
            dots++;
            seg_len = 0;
        } else if (is_alnum_underscore(c)) {
            seg_len++;
        } else {
            return 0;
        }
    }
    return dots >= 1 && seg_len > 0;
}

static int valid_component_class(const char *cls, size_t len) {
    if (!cls || len == 0 || len > BROKER_MAX_ACTIVITY_BYTES) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)cls[i];
        if (!(is_alnum_underscore(c) || c == '.' || c == '$')) {
            return 0;
        }
        if (c == '.' && i + 1 < len && cls[i + 1] == '.') {
            return 0;
        }
    }
    return 1;
}

static int is_safe_apk_path(const char *p, size_t len) {
    if (!p || len == 0 || len > BROKER_MAX_APK_PATH_BYTES) {
        return 0;
    }
    if (len < 4 || memcmp(p + len - 4, ".apk", 4) != 0) {
        return 0;
    }
    const char *tmp_pfx = "/data/local/tmp/";
    const char *stg_pfx = "/data/adb/sandbox_guard/staging/";
    size_t tmp_len = strlen(tmp_pfx);
    size_t stg_len = strlen(stg_pfx);
    int in_tmp = (len > tmp_len && memcmp(p, tmp_pfx, tmp_len) == 0);
    int in_stg = (len > stg_len && memcmp(p, stg_pfx, stg_len) == 0);
    if (!in_tmp && !in_stg) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c <= 0x20u || c == ';' || c == '&' || c == '|' || c == '$' ||
            c == '`' || c == '\'' || c == '"' || c == '\\') {
            return 0;
        }
        if (c == '.' && i + 1 < len && p[i + 1] == '.') {
            return 0;
        }
    }
    return 1;
}

typedef enum op_kind {
    OP_INVALID = 0,
    OP_GET_STATUS,
    OP_IMPORT_EXISTING,
    OP_INSTALL_APK,
    OP_START_VPN,
    OP_PAUSE_VPN,
    OP_RELOAD_CONFIG,
    OP_SYNC_HIDE_APPS,
    OP_RUN_PROBE,
    OP_LAUNCH_APP,
    OP_STOP_APP,
    OP_REMOVE_APP
} op_kind_t;

static op_kind_t parse_op(const char *s, size_t len) {
    struct op_entry {
        const char *name;
        op_kind_t kind;
    };
    static const struct op_entry table[] = {
        {"GET_STATUS", OP_GET_STATUS},
        {"IMPORT_EXISTING", OP_IMPORT_EXISTING},
        {"INSTALL_APK", OP_INSTALL_APK},
        {"START_VPN", OP_START_VPN},
        {"PAUSE_VPN", OP_PAUSE_VPN},
        {"RELOAD_CONFIG", OP_RELOAD_CONFIG},
        {"SYNC_HIDE_APPS", OP_SYNC_HIDE_APPS},
        {"RUN_PROBE", OP_RUN_PROBE},
        {"LAUNCH_APP", OP_LAUNCH_APP},
        {"STOP_APP", OP_STOP_APP},
        {"REMOVE_APP", OP_REMOVE_APP},
    };
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (strlen(table[i].name) == len && memcmp(s, table[i].name, len) == 0) {
            return table[i].kind;
        }
    }
    return OP_INVALID;
}

static int parse_config_obj(json_cursor_t *c, char *errbuf, size_t errcap) {
    jskip_ws(c);
    if (jconsume_null(c) == 0) {
        return 1; /* config was explicit null */
    }
    if (jconsume_char(c, '{') != 0) {
        set_err(errbuf, errcap, "invalid json: expected config object");
        return -1;
    }
    if (++c->depth > 16) {
        set_err(errbuf, errcap, "invalid json: nesting too deep");
        return -1;
    }
    jskip_ws(c);
    int seen_quic = 0;
    int seen_log = 0;
    if (c->pos < c->len && c->buf[c->pos] == '}') {
        c->pos++;
        c->depth--;
        return 0;
    }
    for (;;) {
        char kbuf[64];
        size_t klen = 0;
        int knul = 0;
        if (jparse_string(c, kbuf, sizeof(kbuf), &klen, &knul) != 0 || knul || klen >= sizeof(kbuf)) {
            set_err(errbuf, errcap, "invalid json: bad config key");
            return -1;
        }
        if (jconsume_char(c, ':') != 0) {
            set_err(errbuf, errcap, "invalid json: expected ':' in config");
            return -1;
        }
        if (strcmp(kbuf, "quic_udp443_mode") == 0) {
            if (seen_quic) {
                set_err(errbuf, errcap, "invalid json: duplicate config key");
                return -1;
            }
            seen_quic = 1;
            char val[32];
            size_t vlen = 0;
            int vnul = 0;
            if (jconsume_null(c) != 0) {
                if (jparse_string(c, val, sizeof(val), &vlen, &vnul) != 0 || vnul || vlen >= sizeof(val)) {
                    set_err(errbuf, errcap, "invalid quic_udp443_mode");
                    return -1;
                }
                if (vlen > 0 && strcmp(val, "reject") != 0 && strcmp(val, "allow") != 0) {
                    set_err(errbuf, errcap, "invalid quic_udp443_mode %q", val);
                    return -1;
                }
            }
        } else if (strcmp(kbuf, "log_level") == 0) {
            if (seen_log) {
                set_err(errbuf, errcap, "invalid json: duplicate config key");
                return -1;
            }
            seen_log = 1;
            char val[32];
            size_t vlen = 0;
            int vnul = 0;
            if (jconsume_null(c) != 0) {
                if (jparse_string(c, val, sizeof(val), &vlen, &vnul) != 0 || vnul || vlen >= sizeof(val)) {
                    set_err(errbuf, errcap, "invalid log_level");
                    return -1;
                }
                if (vlen > 0 &&
                    strcmp(val, "silent") != 0 &&
                    strcmp(val, "error") != 0 &&
                    strcmp(val, "warning") != 0 &&
                    strcmp(val, "info") != 0 &&
                    strcmp(val, "debug") != 0) {
                    set_err(errbuf, errcap, "invalid log_level %q", val);
                    return -1;
                }
            }
        } else {
            set_err(errbuf, errcap, "invalid json: unknown field \"%s\"", kbuf);
            return -1;
        }
        jskip_ws(c);
        if (c->pos < c->len && c->buf[c->pos] == ',') {
            c->pos++;
            continue;
        }
        if (jconsume_char(c, '}') == 0) {
            break;
        }
        set_err(errbuf, errcap, "invalid json: malformed config object");
        return -1;
    }
    c->depth--;
    return 0;
}

int broker_validate_rpc_request(
    const char *line,
    size_t len,
    broker_req_info_t *out,
    char *errbuf,
    size_t errcap) {
    if (!line || !out) {
        set_err(errbuf, errcap, "empty request");
        return -1;
    }
    if (len > BROKER_MAX_RPC_LINE_BYTES) {
        set_err(errbuf, errcap, "line exceeds %d bytes", BROKER_MAX_RPC_LINE_BYTES);
        return -1;
    }

    size_t start = 0;
    size_t end = len;
    while (start < end && is_ascii_ws((unsigned char)line[start])) {
        start++;
    }
    while (end > start && is_ascii_ws((unsigned char)line[end - 1])) {
        end--;
    }
    size_t tlen = end - start;
    if (tlen == 0) {
        set_err(errbuf, errcap, "empty request");
        return -1;
    }
    if (tlen + 1 > BROKER_MAX_RPC_LINE_BYTES) {
        set_err(errbuf, errcap, "request exceeds %d bytes", BROKER_MAX_RPC_LINE_BYTES);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->trimmed_off = start;
    out->trimmed_len = tlen;

    json_cursor_t c = {line + start, tlen, 0, 0};
    if (jconsume_char(&c, '{') != 0) {
        set_err(errbuf, errcap, "invalid json: expected object");
        return -1;
    }
    c.depth = 1;
    jskip_ws(&c);

    int seen_id = 0, seen_op = 0, seen_pkg = 0, seen_act = 0, seen_apks = 0, seen_cfg = 0;
    char id_buf[BROKER_MAX_ID_BYTES + 2];
    size_t id_len = 0;
    op_kind_t op_kind = OP_INVALID;
    char pkg_buf[BROKER_MAX_PKG_BYTES + 2];
    size_t pkg_len = 0;
    char act_buf[BROKER_MAX_ACTIVITY_BYTES + 2];
    size_t act_len = 0;
    int apk_count = 0;
    int has_bad_apk = 0;
    char bad_apk_buf[64];
    int has_non_null_config = 0;

    if (c.pos < c.len && c.buf[c.pos] == '}') {
        c.pos++;
    } else {
        for (;;) {
            char key[32];
            size_t klen = 0;
            int knul = 0;
            if (jparse_string(&c, key, sizeof(key), &klen, &knul) != 0 || knul || klen >= sizeof(key)) {
                set_err(errbuf, errcap, "invalid json: bad field name");
                return -1;
            }
            if (jconsume_char(&c, ':') != 0) {
                set_err(errbuf, errcap, "invalid json: expected ':'");
                return -1;
            }

            if (strcmp(key, "id") == 0) {
                if (seen_id) {
                    set_err(errbuf, errcap, "invalid json: duplicate id");
                    return -1;
                }
                seen_id = 1;
                int has_nul = 0;
                if (jconsume_null(&c) == 0) {
                    id_len = 0;
                } else {
                    if (jparse_string(&c, id_buf, sizeof(id_buf), &id_len, &has_nul) != 0 || has_nul) {
                        set_err(errbuf, errcap, "invalid request id");
                        return -1;
                    }
                    if (id_len == 0 || id_len > BROKER_MAX_ID_BYTES) {
                        set_err(errbuf, errcap, "invalid request id");
                        return -1;
                    }
                    for (size_t i = 0; i < id_len; i++) {
                        if (id_buf[i] == '\r' || id_buf[i] == '\n' || id_buf[i] == '\t') {
                            set_err(errbuf, errcap, "invalid request id");
                            return -1;
                        }
                    }
                }
            } else if (strcmp(key, "op") == 0) {
                if (seen_op) {
                    set_err(errbuf, errcap, "invalid json: duplicate op");
                    return -1;
                }
                seen_op = 1;
                char op_buf[32];
                size_t op_len = 0;
                int has_nul = 0;
                if (jconsume_null(&c) != 0) {
                    if (jparse_string(&c, op_buf, sizeof(op_buf), &op_len, &has_nul) != 0 || has_nul || op_len >= sizeof(op_buf)) {
                        set_err(errbuf, errcap, "unsupported op");
                        return -1;
                    }
                    op_kind = parse_op(op_buf, op_len);
                }
            } else if (strcmp(key, "pkg") == 0) {
                if (seen_pkg) {
                    set_err(errbuf, errcap, "invalid json: duplicate pkg");
                    return -1;
                }
                seen_pkg = 1;
                int has_nul = 0;
                if (jconsume_null(&c) == 0) {
                    pkg_len = 0;
                } else if (jparse_string(&c, pkg_buf, sizeof(pkg_buf), &pkg_len, &has_nul) != 0 || has_nul || pkg_len > BROKER_MAX_PKG_BYTES) {
                    set_err(errbuf, errcap, "invalid package name");
                    return -1;
                }
            } else if (strcmp(key, "activity") == 0) {
                if (seen_act) {
                    set_err(errbuf, errcap, "invalid json: duplicate activity");
                    return -1;
                }
                seen_act = 1;
                int has_nul = 0;
                if (jconsume_null(&c) == 0) {
                    act_len = 0;
                } else if (jparse_string(&c, act_buf, sizeof(act_buf), &act_len, &has_nul) != 0 || has_nul || act_len > BROKER_MAX_ACTIVITY_BYTES) {
                    set_err(errbuf, errcap, "invalid activity class");
                    return -1;
                }
            } else if (strcmp(key, "apk_paths") == 0) {
                if (seen_apks) {
                    set_err(errbuf, errcap, "invalid json: duplicate apk_paths");
                    return -1;
                }
                seen_apks = 1;
                jskip_ws(&c);
                if (jconsume_null(&c) != 0) {
                    if (jconsume_char(&c, '[') != 0) {
                        set_err(errbuf, errcap, "invalid json: expected apk_paths array");
                        return -1;
                    }
                    if (++c.depth > 16) {
                        set_err(errbuf, errcap, "invalid json: nesting too deep");
                        return -1;
                    }
                    jskip_ws(&c);
                    if (c.pos < c.len && c.buf[c.pos] == ']') {
                        c.pos++;
                    } else {
                        for (;;) {
                            char apath[BROKER_MAX_APK_PATH_BYTES + 2];
                            size_t alen = 0;
                            int anul = 0;
                            if (jparse_string(&c, apath, sizeof(apath), &alen, &anul) != 0) {
                                set_err(errbuf, errcap, "invalid apk_paths item");
                                return -1;
                            }
                            apk_count++;
                            if (!has_bad_apk && (anul || !is_safe_apk_path(apath, alen))) {
                                has_bad_apk = 1;
                                size_t copy_n = alen < sizeof(bad_apk_buf) - 1 ? alen : sizeof(bad_apk_buf) - 1;
                                memcpy(bad_apk_buf, apath, copy_n);
                                bad_apk_buf[copy_n] = '\0';
                            }
                            jskip_ws(&c);
                            if (c.pos < c.len && c.buf[c.pos] == ',') {
                                c.pos++;
                                continue;
                            }
                            if (jconsume_char(&c, ']') == 0) {
                                break;
                            }
                            set_err(errbuf, errcap, "invalid json: malformed apk_paths");
                            return -1;
                        }
                    }
                    c.depth--;
                }
            } else if (strcmp(key, "config") == 0) {
                if (seen_cfg) {
                    set_err(errbuf, errcap, "invalid json: duplicate config");
                    return -1;
                }
                seen_cfg = 1;
                int rc = parse_config_obj(&c, errbuf, errcap);
                if (rc < 0) {
                    return -1;
                }
                if (rc == 0) {
                    has_non_null_config = 1;
                }
            } else {
                set_err(errbuf, errcap, "invalid json: unknown field \"%s\"", key);
                return -1;
            }

            jskip_ws(&c);
            if (c.pos < c.len && c.buf[c.pos] == ',') {
                c.pos++;
                continue;
            }
            if (jconsume_char(&c, '}') == 0) {
                break;
            }
            set_err(errbuf, errcap, "invalid json: malformed object");
            return -1;
        }
    }

    jskip_ws(&c);
    if (c.pos != c.len) {
        set_err(errbuf, errcap, "trailing data after json object");
        return -1;
    }

    if (id_len == 0) {
        set_err(errbuf, errcap, "invalid request id");
        return -1;
    }
    if (op_kind == OP_INVALID) {
        set_err(errbuf, errcap, "unsupported op");
        return -1;
    }
    if (op_kind == OP_IMPORT_EXISTING || op_kind == OP_LAUNCH_APP ||
        op_kind == OP_STOP_APP || op_kind == OP_REMOVE_APP) {
        if (!valid_package_name(pkg_buf, pkg_len)) {
            set_err(errbuf, errcap, "invalid package name");
            return -1;
        }
    } else if (pkg_len > 0 && !valid_package_name(pkg_buf, pkg_len)) {
        set_err(errbuf, errcap, "invalid package name");
        return -1;
    }

    if (act_len > 0) {
        if (op_kind != OP_LAUNCH_APP) {
            set_err(errbuf, errcap, "activity field only allowed on LAUNCH_APP");
            return -1;
        }
        if (!valid_component_class(act_buf, act_len)) {
            set_err(errbuf, errcap, "invalid activity class");
            return -1;
        }
    }

    if (op_kind == OP_INSTALL_APK) {
        if (apk_count == 0 || apk_count > BROKER_MAX_APK_PATHS) {
            set_err(errbuf, errcap, "INSTALL_APK requires 1..32 apk_paths");
            return -1;
        }
        if (has_bad_apk) {
            set_err(errbuf, errcap, "unsafe apk_path %s", bad_apk_buf);
            return -1;
        }
    } else if (apk_count > 0) {
        set_err(errbuf, errcap, "apk_paths only allowed on INSTALL_APK");
        return -1;
    }

    if (has_non_null_config && op_kind != OP_RELOAD_CONFIG) {
        set_err(errbuf, errcap, "config field only allowed on RELOAD_CONFIG");
        return -1;
    }

    memcpy(out->id, id_buf, id_len);
    out->id[id_len] = '\0';
    out->is_install_apk = (op_kind == OP_INSTALL_APK) ? 1 : 0;
    return 0;
}

static size_t append_json_escaped(char *out, size_t cap, size_t pos, const char *s) {
    if (!s) {
        return pos;
    }
    for (size_t i = 0; s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];
        char rep[7];
        size_t rlen = 0;
        if (c == '"') {
            rep[0] = '\\'; rep[1] = '"'; rlen = 2;
        } else if (c == '\\') {
            rep[0] = '\\'; rep[1] = '\\'; rlen = 2;
        } else if (c == '\b') {
            rep[0] = '\\'; rep[1] = 'b'; rlen = 2;
        } else if (c == '\f') {
            rep[0] = '\\'; rep[1] = 'f'; rlen = 2;
        } else if (c == '\n') {
            rep[0] = '\\'; rep[1] = 'n'; rlen = 2;
        } else if (c == '\r') {
            rep[0] = '\\'; rep[1] = 'r'; rlen = 2;
        } else if (c == '\t') {
            rep[0] = '\\'; rep[1] = 't'; rlen = 2;
        } else if (c < 0x20u) {
            (void)snprintf(rep, sizeof(rep), "\\u%04x", (unsigned int)c);
            rlen = 6;
        } else {
            rep[0] = (char)c; rlen = 1;
        }
        if (pos + rlen > cap) {
            break;
        }
        memcpy(out + pos, rep, rlen);
        pos += rlen;
    }
    return pos;
}

size_t broker_format_error_json(const char *id, const char *msg, char *out, size_t outcap) {
    static const char k_fallback[] = "{\"id\":\"\",\"ok\":false,\"error\":\"internal\",\"data\":{}}\n";
    if (!out || outcap < sizeof(k_fallback)) {
        return 0;
    }
    /* Reserve room for closing trailer `","data":{}}\n\0` (15 bytes). */
    const size_t safe_cap = outcap - 15;
    size_t pos = 0;
    const char *p1 = "{\"id\":\"";
    size_t l1 = strlen(p1);
    if (pos + l1 <= safe_cap) {
        memcpy(out + pos, p1, l1);
        pos += l1;
    }
    pos = append_json_escaped(out, safe_cap, pos, id ? id : "");

    const char *p2 = "\",\"ok\":false,\"error\":\"";
    size_t l2 = strlen(p2);
    if (pos + l2 <= safe_cap) {
        memcpy(out + pos, p2, l2);
        pos += l2;
    }
    pos = append_json_escaped(out, safe_cap, pos, msg ? msg : "error");

    const char *p3 = "\",\"data\":{}}\n";
    size_t l3 = strlen(p3);
    if (pos + l3 + 1 <= outcap) {
        memcpy(out + pos, p3, l3);
        pos += l3;
        out[pos] = '\0';
        return pos;
    }

    memcpy(out, k_fallback, sizeof(k_fallback));
    return sizeof(k_fallback) - 1;
}
