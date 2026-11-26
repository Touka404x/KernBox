#include "../broker_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_check_self_context(void) {
    assert(broker_check_self_context("u:r:ksu:s0\0", 11) != 0);
    assert(broker_check_self_context("", 0) != 0);
    assert(broker_check_self_context("u:r:sandbox_broker:s0\n", 22) == 0);
    assert(broker_check_self_context("u:r:sandbox_broker:s0\0\0", 23) == 0);
}

static void test_parse_auth_json(void) {
    int uid = 0;
    assert(broker_parse_auth_json("{\"allowed_user0_uid\":10376}\n", 28, &uid) == 0);
    assert(uid == 10376);

    assert(broker_parse_auth_json("{\"allowed_user0_uid\": 0}", 24, &uid) == 0);
    assert(uid == 0);

    assert(broker_parse_auth_json("{\"allowed_user0_uid\":10376,\"extra\":1}", 37, &uid) != 0);
    assert(broker_parse_auth_json("{\"allowed_user0_uid\":10376,\"allowed_user0_uid\":1}", 49, &uid) != 0);
    assert(broker_parse_auth_json("{\"allowed_user0_uid\":-1}", 24, &uid) != 0);
    assert(broker_parse_auth_json("{\"allowed_user0_uid\":10376} trailing", 36, &uid) != 0);
    assert(broker_parse_auth_json("{}", 2, &uid) != 0);
}

static void test_authorize_peer_matrix(void) {
    const int allow = 10376;
    const char *v1 = "u:r:untrusted_app:s0:c120,c256,c512,c768";
    const char *v2 = "u:r:untrusted_app_32:s0:c120,c256,c512,c768\0";
    assert(broker_authorize_peer(allow, v1, strlen(v1), allow) == 0);
    assert(broker_authorize_peer(allow, v2, strlen(v1) + 4, allow) == 0);

    const char *iso = "u:r:isolated_app:s0:c120,c256";
    const char *iso_all = "u:r:isolated_app_all:s0";
    const char *u10_ctx = "u:r:untrusted_app:s0:c10";
    const char *plat = "u:r:platform_app:s0";
    const char *sh = "u:r:shell:s0";
    const char *ok = "u:r:untrusted_app:s0";

    assert(broker_authorize_peer(allow, iso, strlen(iso), allow) != 0);
    assert(broker_authorize_peer(allow, iso_all, strlen(iso_all), allow) != 0);
    assert(broker_authorize_peer(1010376, u10_ctx, strlen(u10_ctx), allow) != 0);
    assert(broker_authorize_peer(10377, ok, strlen(ok), allow) != 0);
    assert(broker_authorize_peer(0, ok, strlen(ok), allow) != 0);
    assert(broker_authorize_peer(allow, plat, strlen(plat), allow) != 0);
    assert(broker_authorize_peer(allow, sh, strlen(sh), allow) != 0);
    assert(broker_authorize_peer(allow, ok, strlen(ok), 0) != 0);
}

static void test_validate_rpc_request(void) {
    broker_req_info_t info;
    char err[256];

    const char *r1 = "  {\"id\":\"r-1\",\"op\":\"GET_STATUS\"}\r\n";
    assert(broker_validate_rpc_request(r1, strlen(r1), &info, err, sizeof(err)) == 0);
    assert(strcmp(info.id, "r-1") == 0);
    assert(info.is_install_apk == 0);
    assert(info.trimmed_off == 2);

    const char *r_inst = "{\"id\":\"inst-1\",\"op\":\"INSTALL_APK\",\"apk_paths\":[\"/data/local/tmp/base.apk\",\"/data/adb/sandbox_guard/staging/s.apk\"]}";
    assert(broker_validate_rpc_request(r_inst, strlen(r_inst), &info, err, sizeof(err)) == 0);
    assert(strcmp(info.id, "inst-1") == 0);
    assert(info.is_install_apk == 1);

    const char *r_launch = "{\"id\":\"l-1\",\"op\":\"LAUNCH_APP\",\"pkg\":\"com.example.app\",\"activity\":\".MainActivity\"}";
    assert(broker_validate_rpc_request(r_launch, strlen(r_launch), &info, err, sizeof(err)) == 0);

    const char *r_cfg = "{\"id\":\"c-1\",\"op\":\"RELOAD_CONFIG\",\"config\":{\"quic_udp443_mode\":\"allow\",\"log_level\":\"info\"}}";
    assert(broker_validate_rpc_request(r_cfg, strlen(r_cfg), &info, err, sizeof(err)) == 0);

    const char *bad_cases[] = {
        "",
        "{\"id\":\"1\",\"op\":\"SHELL_EXEC\"}",
        "{\"id\":\"1\",\"op\":\"IMPORT_EXISTING\",\"pkg\":\"com.foo;id\"}",
        "{\"id\":\"1\",\"op\":\"IMPORT_EXISTING\"}",
        "{\"id\":\"1\",\"op\":\"GET_STATUS\",\"extra\":1}",
        "{\"id\":\"1\",\"op\":\"GET_STATUS\",\"id\":\"2\"}",
        "{\"id\":\"1\",\"op\":\"GET_STATUS\",\"activity\":\".Main\"}",
        "{\"id\":\"1\",\"op\":\"GET_STATUS\",\"apk_paths\":[\"/data/local/tmp/a.apk\"]}",
        "{\"id\":\"1\",\"op\":\"GET_STATUS\",\"config\":{\"quic_udp443_mode\":\"allow\"}}",
        "{\"id\":\"1\",\"op\":\"INSTALL_APK\",\"apk_paths\":[\"/sdcard/a.apk\"]}",
        "{\"id\":\"1\",\"op\":\"INSTALL_APK\",\"apk_paths\":[\"/data/local/tmp/../a.apk\"]}",
        "{\"id\":\"1\",\"op\":\"INSTALL_APK\",\"apk_paths\":[\"/data/local/tmp/a;b.apk\"]}",
        "{\"id\":\"1\",\"op\":\"INSTALL_APK\",\"apk_paths\":[]}",
        "{\"id\":\"1\",\"op\":\"RELOAD_CONFIG\",\"config\":{\"quic_udp443_mode\":\"bypass\"}}",
        "{\"id\":\"1\",\"op\":\"GET_STATUS\"} trailing",
        "{\"id\":\"1\\u0000\",\"op\":\"GET_STATUS\"}",
    };
    for (size_t i = 0; i < sizeof(bad_cases) / sizeof(bad_cases[0]); i++) {
        assert(broker_validate_rpc_request(bad_cases[i], strlen(bad_cases[i]), &info, err, sizeof(err)) != 0);
    }

    /* Exact 8192 bytes without newline would become 8193 with '\n' forwarded -> must be rejected. */
    char exact8192[8193];
    const char *pfx = "{\"id\":\"big\",\"op\":\"GET_STATUS\",\"pkg\":\"com.a.";
    size_t plen = strlen(pfx);
    memcpy(exact8192, pfx, plen);
    memset(exact8192 + plen, 'a', 8192 - plen - 2);
    exact8192[8190] = '"';
    exact8192[8191] = '}';
    exact8192[8192] = '\0';
    assert(broker_validate_rpc_request(exact8192, 8192, &info, err, sizeof(err)) != 0);

    /* Reject >32 APK paths. */
    char thirty3[2048];
    size_t pos = 0;
    pos += (size_t)snprintf(thirty3 + pos, sizeof(thirty3) - pos, "{\"id\":\"many\",\"op\":\"INSTALL_APK\",\"apk_paths\":[");
    for (int i = 0; i < 33; i++) {
        pos += (size_t)snprintf(thirty3 + pos, sizeof(thirty3) - pos, "%s\"/data/local/tmp/s%d.apk\"", i ? "," : "", i);
    }
    pos += (size_t)snprintf(thirty3 + pos, sizeof(thirty3) - pos, "]}");
    assert(broker_validate_rpc_request(thirty3, pos, &info, err, sizeof(err)) != 0);
}

static void test_format_error_json(void) {
    char out[256];
    size_t n = broker_format_error_json("id\"1", "bad\\line\nctrl", out, sizeof(out));
    assert(n > 0);
    assert(out[n - 1] == '\n');
    assert(strcmp(out, "{\"id\":\"id\\\"1\",\"ok\":false,\"error\":\"bad\\\\line\\nctrl\",\"data\":{}}\n") == 0);
}

int main(void) {
    test_check_self_context();
    test_parse_auth_json();
    test_authorize_peer_matrix();
    test_validate_rpc_request();
    test_format_error_json();
    printf("NATIVE_BROKER_C11_TESTS_PASSED\n");
    return 0;
}
