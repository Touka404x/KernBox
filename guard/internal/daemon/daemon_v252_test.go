package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
