package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestFlushSandboxConnectionsOnlyClosesMatchingInbound(t *testing.T) {
	var mu sync.Mutex
	var deleted []string
	var authHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authHeader = r.Header.Get("Authorization")
		mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"connections":[
				{"id":"jp-1","metadata":{"inboundName":"sandbox-tproxy"}},
				{"id":"sg-1","metadata":{"inboundName":"tproxy-in"}},
				{"id":"jp-2","metadata":{"inboundName":"sandbox-tproxy"}},
				{"id":"bad/id","metadata":{"inboundName":"sandbox-tproxy"}}
			]}`))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/connections/"):
			mu.Lock()
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/connections/"))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	hostPort := strings.TrimPrefix(srv.URL, "http://")
	if err := os.WriteFile(cfgPath, []byte(`{"external-controller":"`+hostPort+`","secret":"topsecret"}`), 0600); err != nil {
		t.Fatal(err)
	}

	closed, err := FlushSandboxConnections(context.Background(), cfgPath, "sandbox-tproxy")
	if err != nil {
		t.Fatal(err)
	}
	if closed != 2 {
		t.Fatalf("expected 2 closed sandbox-tproxy connections, got %d", closed)
	}
	if authHeader != "Bearer topsecret" {
		t.Fatalf("unexpected Authorization header: %q", authHeader)
	}
	sort.Strings(deleted)
	joined := strings.Join(deleted, ",")
	if joined != "jp-1,jp-2" {
		t.Fatalf("must delete ONLY jp-1,jp-2 (never sg-1 or bad/id), got %q", joined)
	}

	// Refuse non-loopback external-controller cleanly.
	badCfg := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badCfg, []byte(`{"external-controller":"192.168.1.50:9097","secret":"x"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadMihomoControllerConfig(badCfg); err == nil {
		t.Fatal("must refuse non-loopback external-controller")
	}

	// Support 0.0.0.0:port, [::]:port, http:// prefix, 0640 group-readable files, and YAML fallback.
	for _, tc := range []struct {
		name     string
		body     string
		wantURL  string
		wantSec  string
	}{
		{"wildcard_v4", `{"external-controller":"0.0.0.0:9097","secret":"s1"}`, "http://127.0.0.1:9097", "s1"},
		{"wildcard_v6", `{"external-controller":"[::]:9097","secret":"s2"}`, "http://[::1]:9097", "s2"},
		{"http_scheme", `{"external-controller":"http://127.0.0.1:9097/","secret":"s3"}`, "http://127.0.0.1:9097", "s3"},
		{"yaml_fallback", "mode: rule\nexternal-controller: \"0.0.0.0:9099\" # clash api\nsecret: 'sec#yaml'\n", "http://127.0.0.1:9099", "sec#yaml"},
		{"yaml_unquoted_hash", "external-controller: 127.0.0.1:9098 # ctrl\nsecret: my#pass # comment\n", "http://127.0.0.1:9098", "my#pass"},
	} {
		p := filepath.Join(dir, tc.name+".cfg")
		if err := os.WriteFile(p, []byte(tc.body), 0640); err != nil {
			t.Fatal(err)
		}
		gotURL, gotSec, err := ReadMihomoControllerConfig(p)
		if err != nil {
			t.Fatalf("%s failed: %v", tc.name, err)
		}
		if gotURL != tc.wantURL || gotSec != tc.wantSec {
			t.Fatalf("%s got (%q, %q) want (%q, %q)", tc.name, gotURL, gotSec, tc.wantURL, tc.wantSec)
		}
	}

	// Ensure HTTP_PROXY cannot hijack loopback REST calls.
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	closed2, err := FlushSandboxConnections(context.Background(), cfgPath, "sandbox-tproxy")
	if err != nil || closed2 != 2 {
		t.Fatalf("expected direct loopback flush ignoring HTTP_PROXY, got closed=%d err=%v", closed2, err)
	}

	// Verify chunked Transfer-Encoding responses and CR/LF header injection rejection.
	chunkedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/connections" {
			fl, _ := w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"connections":[{"id":"chk 1",`))
			if fl != nil {
				fl.Flush()
			}
			_, _ = w.Write([]byte(`"metadata":{"inboundName":"sandbox-tproxy"}}]}`))
			return
		}
		if r.Method == http.MethodDelete && (r.RequestURI == "/connections/chk%201" || r.URL.Path == "/connections/chk 1") {
			if r.RequestURI != "/connections/chk%201" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer chunkedSrv.Close()
	if n, err := flushMihomoInboundURL(context.Background(), chunkedSrv.URL, "", "sandbox-tproxy"); err != nil || n != 1 {
		t.Fatalf("expected chunked flush count=1, got %d err=%v", n, err)
	}
	if _, _, err := loopbackHTTPRequest(context.Background(), "GET", chunkedSrv.URL, "/connections", "bad\r\nInjected: 1"); err == nil {
		t.Fatal("expected CR/LF in secret to be rejected")
	}
}
