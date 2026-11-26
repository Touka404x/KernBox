package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sandbox_guard/internal/android"
	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/netfilter"
)

type v252RecorderRunner struct {
	mu    sync.Mutex
	calls []string
	fn    func(cmdLine string) (string, error)
}

func (r *v252RecorderRunner) Run(_ context.Context, _ time.Duration, _ string, name string, args ...string) (string, error) {
	line := name
	if len(args) > 0 {
		line += " " + strings.Join(args, " ")
	}
	r.mu.Lock()
	r.calls = append(r.calls, line)
	r.mu.Unlock()
	if r.fn != nil {
		return r.fn(line)
	}
	return "", nil
}

func (r *v252RecorderRunner) countPrefix(prefix string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func TestV252AckWakeCooldownAndPIDRecovery(t *testing.T) {
	dir := t.TempDir()
	ackPath := filepath.Join(dir, "sandbox_ack.v1.json")
	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	ex := BuildBlockedExemption(pol, "boot-v252", 1010123, 42)
	ackBytes, err := json.Marshal(contracts.SandboxAckV1{
		ContractVersion:   contracts.ContractVersion,
		AppliedGeneration: 42,
		BootID:            "boot-v252",
		CorePID:           4147,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ackPath, ackBytes, 0600); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{
		bootID:            "boot-v252",
		policy:            pol,
		policyLoaded:      true,
		sandboxAckPath:    ackPath,
		currentExemption:  &ex,
		ackWaitBlocked:    true,
		ackWaitBlockedAt:  time.Now(),
		ackWaitBlockedPID: 4147,
	}

	if d.shouldClearAckBlockOnWake() {
		t.Fatal("expected shouldClearAckBlockOnWake=false for same PID inside cooldown")
	}

	ackNewPID, _ := json.Marshal(contracts.SandboxAckV1{
		ContractVersion:   contracts.ContractVersion,
		AppliedGeneration: 42,
		BootID:            "boot-v252",
		CorePID:           19438,
	})
	if err := os.WriteFile(ackPath, ackNewPID, 0600); err != nil {
		t.Fatal(err)
	}
	if !d.shouldClearAckBlockOnWake() {
		t.Fatal("expected shouldClearAckBlockOnWake=true after proxy PID change")
	}

	d.ackWaitBlockedPID = 19438
	d.ackWaitBlockedAt = time.Now().Add(-11 * time.Second)
	if !d.shouldClearAckBlockOnWake() {
		t.Fatal("expected shouldClearAckBlockOnWake=true after cooldown elapsed")
	}
}

func TestV252StartTProxyFailFastAndSetsLastError(t *testing.T) {
	dir := t.TempDir()
	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark
	pol.ProxyCtlScript = filepath.Join(dir, "missing_proxy.sh")

	runner := &v252RecorderRunner{}
	d := &Daemon{
		nf:                 &netfilter.Controller{Runner: &tproxyMockIPTables{base: newStatefulMockIPTables(false)}, LockPath: filepath.Join(dir, "nf.lock")},
		runner:             runner,
		bootID:             "boot-v252-fastfail",
		policy:             pol,
		policyLoaded:       true,
		cachedID:           &android.VerifiedIdentity{UserID: 10, Serial: 1000, ClientUID: 1010123},
		state:              StateBlockedLocked,
		paused:             false,
		userUnlockedBoot:   true,
		hibernatedPkgsPath: filepath.Join(dir, "hibernated.json"),
		reconcileCh:        make(chan reconcileReq, 4),
		probeTProxyReady:   func(int) bool { return false },
	}

	// Drain reconcileCh asynchronously so requestReconcile never blocks.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for req := range d.reconcileCh {
			if req.reply != nil {
				req.reply <- nil
			}
		}
	}()
	defer func() {
		close(d.reconcileCh)
		<-done
	}()

	_, _, _, err := d.startTProxySandboxWithPriorityTraced(context.Background(), pol, "com.android.chrome")
	if err == nil {
		t.Fatal("expected error when tproxy core is down and auto-start fails")
	}
	if d.lastError == "" {
		t.Fatal("expected d.lastError to record TProxy start failure")
	}
	if got := runner.countPrefix("am start-user"); got != 0 {
		t.Fatalf("expected zero am start-user retries when userUnlockedBoot=true, got %d", got)
	}
}

func TestV252OpReloadConfigTProxyWithoutWorkClientUID(t *testing.T) {
	dir := t.TempDir()
	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark

	runner := &v252RecorderRunner{
		fn: func(cmdLine string) (string, error) {
			if strings.HasPrefix(cmdLine, "cmd package list packages --user 10 -U") {
				return "", errors.New("package not installed in user 10")
			}
			return "", nil
		},
	}

	d := &Daemon{
		runner:       runner,
		policy:       pol,
		policyLoaded: true,
		paused:       true,
		workCfgDir:   dir,
	}

	resp := d.HandleRPC(context.Background(), contracts.RPCRequest{
		ID:     "rc-1",
		Op:     contracts.OpReloadConfig,
		Config: &contracts.RPCConfigOverrides{QuicUDP443Mode: "allow"},
	})
	if !resp.OK {
		t.Fatalf("expected OpReloadConfig to succeed in TProxy mode even without User 10 controller UID, got err=%q", resp.Error)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "u10.pending.json"))
	if err != nil {
		t.Fatalf("expected u10.pending.json to be written: %v", err)
	}
	if !strings.Contains(string(raw), `"quic_udp443_mode":"allow"`) {
		t.Fatalf("unexpected u10.pending.json contents: %s", string(raw))
	}
}

func TestV252BootHealthAndAlertDeduplication(t *testing.T) {
	dir := t.TempDir()
	disabledFlag := filepath.Join(dir, "zygisk_disabled")
	if err := os.WriteFile(disabledFlag, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(dir, "broker_auth.json")
	if err := os.WriteFile(authPath, []byte(`{"allowed_user0_uid":10345}`), 0600); err != nil {
		t.Fatal(err)
	}

	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark

	runner := &v252RecorderRunner{}
	d := &Daemon{
		runner:             runner,
		policy:             pol,
		policyLoaded:       true,
		paused:             true,
		state:              StateBlockedLocked,
		brokerAuthPath:     authPath,
		zygiskDisabledFlag: disabledFlag,
		stealthConfigPath:  filepath.Join(dir, "stealth.json"),
		stealthRuntimePath: filepath.Join(dir, "runtime_stealth.json"),
		probeTProxyReady:   func(int) bool { return true },
	}

	d.checkBootHealthAndAlert(context.Background())
	if !strings.Contains(d.bootAlert, "Zygisk") {
		t.Fatalf("expected bootAlert to report zygisk_disabled, got %q", d.bootAlert)
	}
	if got := runner.countPrefix("cmd notification post"); got != 1 {
		t.Fatalf("expected 1 cmd notification post call, got %d", got)
	}

	// Second check with same condition within cooldown must deduplicate.
	d.checkBootHealthAndAlert(context.Background())
	if got := runner.countPrefix("cmd notification post"); got != 1 {
		t.Fatalf("expected deduplicated cmd notification post count=1, got %d", got)
	}

	// Clearing zygisk_disabled clears bootAlert when paused & auth valid.
	_ = os.Remove(disabledFlag)
	d.checkBootHealthAndAlert(context.Background())
	if d.bootAlert != "" {
		t.Fatalf("expected bootAlert cleared when healthy, got %q", d.bootAlert)
	}
}

func TestV252BuildStatusDataCacheAndInvalidation(t *testing.T) {
	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark

	runner := &v252RecorderRunner{
		fn: func(cmdLine string) (string, error) {
			switch cmdLine {
			case "settings get global private_dns_mode":
				return "off\n", nil
			case "cmd package list packages -3 --user 10":
				return "package:com.android.chrome\npackage:com.google.android.apps.bard\n", nil
			case "cmd package list packages -e --user 10 com.android.vending":
				return "package:com.android.vending\n", nil
			default:
				return "", nil
			}
		},
	}

	d := &Daemon{
		runner:           runner,
		bootID:           "boot-cache-test",
		policy:           pol,
		policyLoaded:     true,
		paused:           true,
		state:            StateBlockedLocked,
		probeTProxyReady: func(int) bool { return true },
	}

	data1 := d.buildStatusData(context.Background())
	apps1, _ := data1["sandbox_apps"].([]string)
	if len(apps1) != 3 {
		t.Fatalf("expected 3 apps (play + 2 user apps), got %v", apps1)
	}
	if got := runner.countPrefix("settings get global private_dns_mode"); got != 1 {
		t.Fatalf("expected 1 settings call on cold build, got %d", got)
	}
	if got := runner.countPrefix("cmd package list"); got != 2 {
		t.Fatalf("expected 2 cmd package list calls on cold build, got %d", got)
	}

	// Second warm build must execute 0 settings / cmd package forks.
	_ = d.buildStatusData(context.Background())
	if got := runner.countPrefix("settings get global private_dns_mode"); got != 1 {
		t.Fatalf("expected warm build to reuse cached private_dns_mode (count=1), got %d", got)
	}
	if got := runner.countPrefix("cmd package list"); got != 2 {
		t.Fatalf("expected warm build to reuse cached sandbox_apps (count=2), got %d", got)
	}

	// Invalidating caches forces refresh cleanly.
	d.invalidateStatusCaches()
	_ = d.buildStatusData(context.Background())
	if got := runner.countPrefix("settings get global private_dns_mode"); got != 2 {
		t.Fatalf("expected settings call count=2 after invalidation, got %d", got)
	}
	if got := runner.countPrefix("cmd package list"); got != 4 {
		t.Fatalf("expected cmd package list count=4 after invalidation, got %d", got)
	}
}

func TestV252HotWakePreservesCachedID(t *testing.T) {
	dir := t.TempDir()
	pol := testPolicy()
	pol.Mode = contracts.ModeTProxy
	pol.TProxyPort = contracts.DefaultTProxyPort
	pol.TProxyMark = contracts.DefaultTProxyMark

	runner := &v252RecorderRunner{}
	d := &Daemon{
		nf:                 &netfilter.Controller{Runner: &tproxyMockIPTables{base: newStatefulMockIPTables(false)}, LockPath: filepath.Join(dir, "nf.lock")},
		runner:             runner,
		bootID:             "boot-hotwake",
		policy:             pol,
		policyLoaded:       true,
		cachedID:           &android.VerifiedIdentity{UserID: 10, Serial: 1000, ClientUID: 1010123},
		paused:             false,
		state:              StateBlockedLocked,
		userUnlockedBoot:   true,
		hibernatedPkgsPath: filepath.Join(dir, "hibernated.json"),
		reconcileCh:        make(chan reconcileReq, 4),
		probeTProxyReady:   func(int) bool { return true },
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for req := range d.reconcileCh {
			if req.invalidateID {
				req.reply <- errors.New("unexpected invalidateID on warm cachedID wake")
				continue
			}
			_ = d.reconcileOnce(context.Background(), req)
			if req.reply != nil {
				req.reply <- nil
			}
		}
	}()
	defer func() {
		close(d.reconcileCh)
		<-done
	}()

	_, _, _, err := d.startTProxySandboxWithPriorityTraced(context.Background(), pol, "com.android.chrome")
	if err != nil {
		t.Fatalf("startTProxySandboxWithPriorityTraced failed: %v", err)
	}
	d.waitMaintenance()

	if got := runner.countPrefix("cmd user list"); got != 0 {
		t.Fatalf("expected 0 VerifyStaticIdentity cmd user list forks on warm wake, got %d", got)
	}
	if got := runner.countPrefix("dumpsys user"); got != 0 {
		t.Fatalf("expected 0 VerifyStaticIdentity dumpsys user forks on warm wake, got %d", got)
	}
}

func TestV252FlushSandboxConnectionsParallel(t *testing.T) {
	var deletedSandbox atomic.Int64
	var deletedHost atomic.Int64

	type connItem struct {
		id      string
		inbound string
	}
	var items []connItem
	for i := 0; i < 16; i++ {
		items = append(items, connItem{id: fmt.Sprintf("sb-%d", i), inbound: "sandbox-tproxy"})
	}
	items = append(items, connItem{id: "host-0", inbound: "host-tproxy"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/connections" {
			w.Header().Set("Content-Type", "application/json")
			var b strings.Builder
			b.WriteString(`{"connections":[`)
			for i, it := range items {
				if i > 0 {
					b.WriteByte(',')
				}
				fmt.Fprintf(&b, `{"id":%q,"metadata":{"inboundName":%q}}`, it.id, it.inbound)
			}
			b.WriteString(`]}`)
			_, _ = w.Write([]byte(b.String()))
			return
		}
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/connections/") {
			id := strings.TrimPrefix(r.URL.Path, "/connections/")
			if strings.HasPrefix(id, "sb-") {
				deletedSandbox.Add(1)
			} else {
				deletedHost.Add(1)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	closed, err := flushMihomoInboundURL(context.Background(), srv.URL, "secret123", "sandbox-tproxy")
	if err != nil {
		t.Fatalf("flushMihomoInboundURL failed: %v", err)
	}
	if closed != 16 || deletedSandbox.Load() != 16 || deletedHost.Load() != 0 {
		t.Fatalf("unexpected parallel flush counts: closed=%d sb=%d host=%d", closed, deletedSandbox.Load(), deletedHost.Load())
	}
}

