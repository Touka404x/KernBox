package rpc

import (
	"bytes"
	"strings"
	"testing"

	"sandbox_guard/internal/contracts"
)

func TestParseAndValidateRequest(t *testing.T) {
	// Valid ops
	for _, line := range []string{
		`{"id":"req-1","op":"GET_STATUS"}`,
		`{"id":"req-2","op":"IMPORT_EXISTING","pkg":"com.android.chrome"}`,
		`{"id":"req-3","op":"START_VPN","pkg":""}`,
		`{"id":"req-4","op":"PAUSE_VPN"}`,
		`{"id":"req-5","op":"RELOAD_CONFIG","config":{"quic_udp443_mode":"allow","log_level":"info"}}`,
		`{"id":"req-6","op":"SYNC_HIDE_APPS"}`,
		`{"id":"req-7","op":"RUN_PROBE"}`,
		`{"id":"req-8","op":"INSTALL_APK","apk_paths":["/data/local/tmp/base.apk","` + contracts.StagingDir + `/split_config.arm64_v8a.apk"]}`,
		`{"id":"req-9","op":"LAUNCH_APP","pkg":"com.google.android.apps.bard","activity":"com.google.android.apps.bard.shellapp.BardEntryPointActivity"}`,
		`{"id":"req-10","op":"LAUNCH_APP","pkg":"com.android.vending"}`,
	} {
		if _, err := ParseAndValidateRequest([]byte(line)); err != nil {
			t.Fatalf("valid line %s rejected: %v", line, err)
		}
	}

	// Reject oversized >8192B
	oversized := `{"id":"big","op":"GET_STATUS","pkg":"` + strings.Repeat("a", contracts.MaxRPCLineBytes) + `"}`
	if _, err := ParseAndValidateRequest([]byte(oversized)); err == nil {
		t.Fatal("accepted >8192B RPC request")
	}

	// Reject shell injection / malformed package names / unknown ops / unknown fields
	badLines := []string{
		`{"id":"1","op":"SHELL_EXEC"}`,
		`{"id":"1","op":"IMPORT_EXISTING","pkg":"com.foo;id"}`,
		`{"id":"1","op":"IMPORT_EXISTING","pkg":"com.foo && rm -rf /"}`,
		`{"id":"1","op":"IMPORT_EXISTING","pkg":"../evil"}`,
		`{"id":"1","op":"IMPORT_EXISTING","pkg":"singleword"}`,
		`{"id":"1","op":"IMPORT_EXISTING","pkg":""}`,
		`{"id":"","op":"GET_STATUS"}`,
		`{"id":"1","op":"GET_STATUS","extra":true}`,
		`{"id":"1","op":"RELOAD_CONFIG","config":{"quic_udp443_mode":"bypass"}}`,
		`{"id":"1","op":"GET_STATUS","config":{"log_level":"info"}}`,
		`{"id":"1","op":"INSTALL_APK"}`,
		`{"id":"1","op":"INSTALL_APK","apk_paths":["/data/local/tmp/../evil.apk"]}`,
		`{"id":"1","op":"INSTALL_APK","apk_paths":["/sdcard/Download/app.apk"]}`,
		`{"id":"1","op":"INSTALL_APK","apk_paths":["/data/local/tmp/app.zip"]}`,
		`{"id":"1","op":"INSTALL_APK","apk_paths":["/data/local/tmp/a;id.apk"]}`,
		`{"id":"1","op":"GET_STATUS","apk_paths":["/data/local/tmp/base.apk"]}`,
		`{"id":"1","op":"LAUNCH_APP","pkg":""}`,
		`{"id":"1","op":"LAUNCH_APP","pkg":"com.foo;id"}`,
		`{"id":"1","op":"LAUNCH_APP","pkg":"com.android.vending","activity":"../evil"}`,
		`{"id":"1","op":"LAUNCH_APP","pkg":"com.android.vending","activity":".Main;id"}`,
		`{"id":"1","op":"GET_STATUS","activity":".Main"}`,
	}
	for _, bad := range badLines {
		if _, err := ParseAndValidateRequest([]byte(bad)); err == nil {
			t.Fatalf("accepted bad RPC line: %s", bad)
		}
	}
}

func TestReadLineBounded(t *testing.T) {
	line, err := ReadLineBounded(bytes.NewBufferString(`{"id":"1","op":"GET_STATUS"}`+"\n"), 128)
	if err != nil || !strings.Contains(string(line), "GET_STATUS") {
		t.Fatalf("failed valid bounded read: %v %q", err, string(line))
	}
	tooLong := bytes.NewBufferString(strings.Repeat("x", 8193) + "\n")
	if _, err := ReadLineBounded(tooLong, contracts.MaxRPCLineBytes); err == nil {
		t.Fatal("accepted line exceeding 8192 bytes")
	}
}
