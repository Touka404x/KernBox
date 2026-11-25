package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/rpc"
	"sandbox_guard/internal/sysio"
)

func TestCheckSelfContext(t *testing.T) {
	dir := t.TempDir()
	attr := filepath.Join(dir, "current")

	if err := os.WriteFile(attr, []byte("u:r:ksu:s0\x00"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckSelfContext(attr, false); err == nil {
		t.Fatal("accepted non-broker context u:r:ksu:s0")
	}
	if _, err := CheckSelfContext(attr, true); err != nil {
		t.Fatalf("allowTest failed: %v", err)
	}

	if err := os.WriteFile(attr, []byte(contracts.SELinuxBrokerCtx+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := CheckSelfContext(attr, false); err != nil || got != contracts.SELinuxBrokerCtx {
		t.Fatalf("rejected valid broker context: got=%q err=%v", got, err)
	}
}

func TestAuthorizePeerMatrix(t *testing.T) {
	const allowedUID = 10376
	valid := []sysio.PeerCredentials{
		{PID: 100, UID: allowedUID, GID: allowedUID, Context: "u:r:untrusted_app:s0:c120,c256,c512,c768"},
		{PID: 101, UID: allowedUID, GID: allowedUID, Context: "u:r:untrusted_app_32:s0:c120,c256,c512,c768\x00"},
	}
	for _, c := range valid {
		if err := AuthorizePeer(c, allowedUID); err != nil {
			t.Fatalf("valid peer %+v rejected: %v", c, err)
		}
	}

	invalid := []struct {
		name  string
		creds sysio.PeerCredentials
		allow int
	}{
		{"isolated_app", sysio.PeerCredentials{UID: allowedUID, Context: "u:r:isolated_app:s0:c120,c256"}, allowedUID},
		{"isolated_app_compute", sysio.PeerCredentials{UID: allowedUID, Context: "u:r:isolated_app_all:s0"}, allowedUID},
		{"work_uid_1010376", sysio.PeerCredentials{UID: 1010376, Context: "u:r:untrusted_app:s0:c10"}, allowedUID},
		{"wrong_user0_uid", sysio.PeerCredentials{UID: 10377, Context: "u:r:untrusted_app:s0"}, allowedUID},
		{"root_uid_0", sysio.PeerCredentials{UID: 0, Context: "u:r:untrusted_app:s0"}, allowedUID},
		{"platform_app_domain", sysio.PeerCredentials{UID: allowedUID, Context: "u:r:platform_app:s0"}, allowedUID},
		{"shell_domain", sysio.PeerCredentials{UID: allowedUID, Context: "u:r:shell:s0"}, allowedUID},
		{"revoked_allowed_uid_0", sysio.PeerCredentials{UID: allowedUID, Context: "u:r:untrusted_app:s0"}, 0},
	}
	for _, tc := range invalid {
		if err := AuthorizePeer(tc.creds, tc.allow); err == nil {
			t.Fatalf("case %s should have been rejected", tc.name)
		}
	}
}

func TestBrokerForwardingAndRejection(t *testing.T) {
	dir := t.TempDir()
	authPath := filepath.Join(dir, "broker_auth.json")
	guardSock := filepath.Join(dir, "guard.sock")
	clientSock := filepath.Join(dir, "ctrl.sock")

	if err := os.WriteFile(authPath, []byte(`{"allowed_user0_uid":10376}`), 0600); err != nil {
		t.Fatal(err)
	}

	// Start mock guard.sock
	gln, err := net.Listen("unix", guardSock)
	if err != nil {
		t.Fatal(err)
	}
	defer gln.Close()
	go func() {
		for {
			c, err := gln.Accept()
			if err != nil {
				return
			}
			line, err := rpc.ReadLineBounded(c, contracts.MaxRPCLineBytes)
			if err == nil {
				req, perr := rpc.ParseAndValidateRequest(line)
				if perr == nil {
					_ = json.NewEncoder(c).Encode(contracts.RPCResponse{
						ID:   req.ID,
						OK:   true,
						Data: map[string]any{"op": req.Op},
					})
					_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
					var eof [1]byte
					_, _ = c.Read(eof[:])
				}
			}
			_ = c.Close()
		}
	}()

	var credMu sync.Mutex
	var currentCreds sysio.PeerCredentials
	var credErr error
	setCreds := func(creds sysio.PeerCredentials, cerr error) {
		credMu.Lock()
		currentCreds = creds
		credErr = cerr
		credMu.Unlock()
	}
	cfg := BrokerConfig{
		ClientSockPath: clientSock,
		GuardSockPath:  guardSock,
		AuthFilePath:   authPath,
		AllowTestCtx:   true,
		GetPeerCreds: func(conn net.Conn) (sysio.PeerCredentials, error) {
			credMu.Lock()
			defer credMu.Unlock()
			return currentCreds, credErr
		},
	}
	_, stop, err := ServeBroker(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	call := func(line string, writeBeforeRead bool) contracts.RPCResponse {
		c, err := net.DialTimeout("unix", clientSock, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if writeBeforeRead {
			_, _ = c.Write([]byte(line))
		}
		raw, err := rpc.ReadLineBounded(c, contracts.MaxRPCRespBytes)
		if err != nil {
			t.Fatalf("call(%d bytes) read failed: %v", len(line), err)
		}
		var resp contracts.RPCResponse
		if err := json.Unmarshal(bytes.TrimSpace(raw), &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// 1. Authorized User 0 untrusted_app -> forwarded cleanly
	setCreds(sysio.PeerCredentials{UID: 10376, Context: "u:r:untrusted_app_32:s0:c120,c256"}, nil)
	r1 := call(`{"id":"1","op":"GET_STATUS"}`+"\n", true)
	if !r1.OK || r1.ID != "1" {
		t.Fatalf("authorized RPC failed: %+v", r1)
	}

	expectSilentClose := func(label string) {
		t.Helper()
		c, err := net.DialTimeout("unix", clientSock, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		var buf [16]byte
		n, rerr := c.Read(buf[:])
		if n != 0 || !errors.Is(rerr, io.EOF) {
			t.Fatalf("%s: expected silent EOF close, got n=%d data=%q err=%v", label, n, string(buf[:n]), rerr)
		}
	}

	// 2. isolated_app dropped silently (no oracle banner leaked)
	setCreds(sysio.PeerCredentials{UID: 10376, Context: "u:r:isolated_app:s0:c120"}, nil)
	expectSilentClose("isolated_app")

	// 3. SO_PEERCRED error dropped silently
	setCreds(sysio.PeerCredentials{}, errors.New("bad cred"))
	expectSilentClose("cred_err")
	setCreds(sysio.PeerCredentials{}, nil)

	// 3b. Work user (User 10) dropped silently
	setCreds(sysio.PeerCredentials{UID: 1010376, Context: "u:r:untrusted_app:s0:c10"}, nil)
	expectSilentClose("work_user_u10")

	// 4. Oversized >8192B rejected before forwarding
	setCreds(sysio.PeerCredentials{UID: 10376, Context: "u:r:untrusted_app:s0"}, nil)
	big := `{"id":"4","op":"GET_STATUS","pkg":"` + strings.Repeat("a", contracts.MaxRPCLineBytes) + `"}` + "\n"
	r4 := call(big, true)
	if r4.OK || !strings.Contains(r4.Error, "8192") {
		t.Fatalf("oversized request not rejected: %+v", r4)
	}
}
