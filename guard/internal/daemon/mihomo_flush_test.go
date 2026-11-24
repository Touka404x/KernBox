package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
}
