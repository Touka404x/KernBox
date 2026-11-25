package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"sandbox_guard/internal/android"
	"sandbox_guard/internal/apkcert"
	"sandbox_guard/internal/buildinfo"
	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/netfilter"
	"sandbox_guard/internal/oem"
	"sandbox_guard/internal/rpc"
	"sandbox_guard/internal/sysio"
)

type Logger struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func NewLogger(path string) *Logger { return &Logger{path: path} }

func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	l.size = 0
	return err
}

func (l *Logger) Printf(format string, args ...any) {
	if l == nil || l.path == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil && l.size > 128<<10 {
		_ = l.f.Close()
		l.f = nil
		_ = os.Rename(l.path, l.path+".1")
		l.size = 0
	}
	if l.f == nil {
		if st, err := os.Stat(l.path); err == nil {
			if st.Size() > 128<<10 {
				_ = os.Rename(l.path, l.path+".1")
				l.size = 0
			} else {
				l.size = st.Size()
			}
		}
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return
		}
		l.f = f
	}
	n, _ := fmt.Fprintf(l.f, "%s %s\n", time.Now().Format("01-02 15:04:05.000"), fmt.Sprintf(format, args...))
	if n > 0 {
		l.size += int64(n)
	}
}

// LaunchTrace records monotonic microsecond phase durations for root app launches.
type LaunchTrace struct {
	Op          string `json:"op"`
	Pkg         string `json:"pkg"`
	ThawUs      int64  `json:"thaw_us"`
	RestoreUs   int64  `json:"restore_us"`
	ReconcileUs int64  `json:"reconcile_us"`
	LaunchUs    int64  `json:"launch_us"`
	TotalUs     int64  `json:"total_us"`
	FastPath    bool   `json:"fast_path"`
	Timestamp   string `json:"ts"`
}

type Daemon struct {
	nf       *netfilter.Controller
	runner   android.Runner
	log      *Logger
	bootID   string
	resolver sysio.SafeResolver
	watchers *InotifyWatcher

	workCfgDir         string
	desiredStatePath   string
	exemptionPath      string
	sandboxAckPath     string
	upgradeFencePath   string
	stealthConfigPath    string
	stealthRuntimePath   string
	zygiskDisabledFlag   string
	stealthBootTriesPath string
	perfConfigPath     string
	prunedPkgsPath     string
	hibernatedPkgsPath string
	cgroupRoot         string
	asoundRoot         string
	mainConfigPath     string
	packagesListPath   string
	proxyCtlScript     string
	apkStagingDirs     []string

	mu                 sync.Mutex
	policy             contracts.Policy
	policyLoaded       bool
	cachedID           *android.VerifiedIdentity
	paused             bool
	fence              contracts.UpgradeFence
	currentExemption   *contracts.ExemptionV1
	lastGen            uint64
	lastPendingGen     uint64
	state              State
	ackWaitDeadlineNs  int64
	ackWaitBlocked     bool
	switchGraceUntilNs int64
	lastError          string
	lastSession        *netfilter.ActiveSession
	lastVPNStatus      *contracts.VPNStatus
	lastRawArmed       bool
	lastOpen           bool
	lastAppliedSpec    *netfilter.GateSpec
	perfCfg            PerfConfig
	perfLoaded         bool
	bloatPrunedOnce    bool
	lastPolicySyncHash string

	// Optional OS probes (nil defaults to live android/net/sysio probes; overridden in unit tests).
	probeFastSession  func(bootID string, clientUID int, status *contracts.VPNStatus) (*netfilter.ActiveSession, bool)
	probeTunAlive     func(tunIf string, expectedIfindex int) bool
	probeServiceAlive func(clientUID int) bool
	probeTProxyReady  func(port int) bool
	nowMonoNsFn       func() int64
	userWakeTimeout   time.Duration

	// Recovery state (zero polling while idle; bounded backoff only when VPN missing while wanted)
	kickAttempts int
	kickNextAt   time.Time

	brokerAuthPath         string
	desiredStateMu         sync.Mutex
	lifecycleMu            sync.Mutex
	maintWg                sync.WaitGroup
	maintCancel            context.CancelFunc
	shuttingDown           bool
	lastBootPauseEnforceAt time.Time
	superviseCtx           context.Context
	launcherCache          map[string]string
	userUnlockedBoot       bool
	launchTraces           []LaunchTrace
	wakeSeq                uint64
	hotEscalating          bool

	reconcileCh    chan reconcileReq
	timerRefreshCh chan struct{}
	quitCh         chan struct{}
	quitOnce       sync.Once
}

type reconcileReq struct {
	hintHandoff    bool
	clearAckBlock  bool
	invalidateID   bool
	refreshCert    bool
	syncHide       bool
	reply          chan error
}

func NewDaemon() (*Daemon, error) {
	bootID, err := sysio.ReadBootID()
	if err != nil {
		return nil, err
	}
	d := &Daemon{
		nf:               netfilter.NewController(),
		runner:           netfilter.ExecRunner{},
		log:              NewLogger(filepath.Join(contracts.GuardHome, "guard.log")),
		bootID:           bootID,
		state:            StateBlockedBoot,
		workCfgDir:         contracts.WorkCfgDir,
		desiredStatePath:   contracts.DesiredStatePath,
		exemptionPath:      contracts.ExemptionPath,
		sandboxAckPath:     contracts.SandboxAckPath,
		upgradeFencePath:   contracts.UpgradeFencePath,
		stealthConfigPath:    contracts.StealthConfigPath,
		stealthRuntimePath:   contracts.StealthRuntimePath,
		zygiskDisabledFlag:   contracts.ZygiskDisabledFlag,
		stealthBootTriesPath: contracts.StealthBootTriesPath,
		perfConfigPath:     contracts.PerfConfigPath,
		prunedPkgsPath:     contracts.PrunedPkgsPath,
		mainConfigPath:     contracts.MainConfigPath,
		packagesListPath:   contracts.PackagesListPath,
		proxyCtlScript:     contracts.MainCtlScript,
		reconcileCh:        make(chan reconcileReq, 16),
		timerRefreshCh:     make(chan struct{}, 1),
		quitCh:             make(chan struct{}),
	}
	d.loadPersistedState()
	return d, nil
}

func (d *Daemon) resolvedPerfPath() string {
	if d.perfConfigPath != "" {
		return d.perfConfigPath
	}
	return contracts.PerfConfigPath
}

func (d *Daemon) resolvedPrunedPath() string {
	if d.prunedPkgsPath != "" {
		return d.prunedPkgsPath
	}
	return contracts.PrunedPkgsPath
}

func (d *Daemon) resolvedHibernatedPath() string {
	if d.hibernatedPkgsPath != "" {
		return d.hibernatedPkgsPath
	}
	return contracts.HibernatedPkgsPath
}

func (d *Daemon) resolvedMainConfigPath(policy ...contracts.Policy) string {
	if d.mainConfigPath != "" {
		return d.mainConfigPath
	}
	if len(policy) > 0 {
		return policy[0].EffectiveProxyConfigPath()
	}
	return contracts.MainConfigPath
}

func (d *Daemon) resolvedInboundName(perf PerfConfig, policy contracts.Policy) string {
	if policy.ProxyInboundName != "" {
		return policy.ProxyInboundName
	}
	return perf.SandboxInboundName
}

func (d *Daemon) getPerfConfig() PerfConfig {
	d.mu.Lock()
	loaded := d.perfLoaded
	cfg := d.perfCfg
	d.mu.Unlock()
	if loaded {
		cfg.Normalize()
		return cfg
	}
	cfg = LoadPerfConfig(d.resolvedPerfPath())
	d.mu.Lock()
	d.perfCfg = cfg
	d.perfLoaded = true
	d.mu.Unlock()
	return cfg
}

func (d *Daemon) setPerfConfig(cfg PerfConfig) {
	cfg.Normalize()
	d.mu.Lock()
	d.perfCfg = cfg
	d.perfLoaded = true
	d.lastPolicySyncHash = ""
	d.mu.Unlock()
}

func (d *Daemon) isPaused() bool {
	d.mu.Lock()
	p := d.paused
	d.mu.Unlock()
	return p
}

func (d *Daemon) resolvedBrokerAuthPath() string {
	if d.brokerAuthPath != "" {
		return d.brokerAuthPath
	}
	return contracts.BrokerAuthPath
}

func (d *Daemon) brokerAuthWriteOpts() sysio.WriteAtomicOptions {
	if d.brokerAuthPath != "" {
		return sysio.WriteAtomicOptions{Perm: 0600, UID: -1, GID: -1}
	}
	return sysio.WriteAtomicOptions{Perm: 0600, UID: 0, GID: 0, SELinux: contracts.SELinuxPrivFile}
}

func (d *Daemon) daemonBgContext() context.Context {
	d.mu.Lock()
	ctx := d.superviseCtx
	d.mu.Unlock()
	if ctx != nil {
		return ctx
	}
	return context.Background()
}

func (d *Daemon) cachedLauncher(pkg string) string {
	d.mu.Lock()
	comp := d.launcherCache[pkg]
	d.mu.Unlock()
	return comp
}

func (d *Daemon) setCachedLauncher(pkg, comp string) {
	if pkg == "" || comp == "" {
		return
	}
	d.mu.Lock()
	if d.launcherCache == nil {
		d.launcherCache = make(map[string]string, 8)
	}
	d.launcherCache[pkg] = comp
	d.mu.Unlock()
}

func (d *Daemon) evictCachedLauncher(pkg string) {
	d.mu.Lock()
	delete(d.launcherCache, pkg)
	d.mu.Unlock()
}

func (d *Daemon) invalidateLaunchCaches() {
	d.mu.Lock()
	d.launcherCache = nil
	d.mu.Unlock()
}

func (d *Daemon) recordLaunchTrace(tr LaunchTrace) {
	d.mu.Lock()
	const maxTraces = 16
	if len(d.launchTraces) >= maxTraces {
		copy(d.launchTraces, d.launchTraces[1:])
		d.launchTraces[len(d.launchTraces)-1] = tr
	} else {
		d.launchTraces = append(d.launchTraces, tr)
	}
	d.mu.Unlock()
}

func (d *Daemon) getLaunchTraces() []LaunchTrace {
	d.mu.Lock()
	out := make([]LaunchTrace, len(d.launchTraces))
	copy(out, d.launchTraces)
	d.mu.Unlock()
	return out
}

func (d *Daemon) waitMaintenance() {
	d.maintWg.Wait()
}

func (d *Daemon) bumpWakeSeq() uint64 {
	d.mu.Lock()
	d.wakeSeq++
	seq := d.wakeSeq
	d.mu.Unlock()
	return seq
}

func (d *Daemon) cancelMaintenance() {
	d.mu.Lock()
	cancel := d.maintCancel
	d.maintCancel = nil
	d.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (d *Daemon) loadPersistedState() {
	if p, err := ReadPolicy(); err == nil {
		d.policy = p
		d.policyLoaded = true
	}
	if ex, err := ReadExemption(contracts.ExemptionPath); err == nil {
		d.lastGen = ex.Generation
		if ex.BootID == d.bootID {
			d.currentExemption = &ex
		}
	}
	if ds, err := ReadDesiredState(); err == nil {
		d.paused = ds.Paused
	}
	if f, err := ReadUpgradeFence(d.bootID); err == nil {
		d.fence = f
	}
	d.perfCfg = SyncPerfConfig(d.resolvedPerfPath())
	d.perfLoaded = true
}

func (d *Daemon) syncPolicies(ctx context.Context, policy contracts.Policy) (android.AppPolicySyncResult, error) {
	perf := d.getPerfConfig()
	cfgPath, _, _ := d.resolvedStealthPaths()
	stealthCfg := loadExistingOrDefaultStealth(cfgPath, policy.UserID, 0)
	baseLocale := stealthCfg.Locale
	if baseLocale == "" {
		baseLocale = "en-US"
	}
	btName := ""
	if stealthCfg.SpoofBluetooth {
		btName = stealthCfg.DeviceName
	}
	res, err := android.SyncSandboxAppPoliciesWithOpts(ctx, d.runner, policy.UserID, android.PolicySyncOptions{
		CallerPackage:       policy.EffectiveCallerPackage(),
		DefaultLocale:       baseLocale,
		PreserveUserLocales: perf.PreserveUserLocales && stealthCfg.PreserveUserLocales,
		LocaleOverrides:     perf.LocaleOverrides,
		BluetoothDeviceName: btName,
	})
	if err == nil && res.PackagesHash != "" {
		d.mu.Lock()
		d.lastPolicySyncHash = res.PackagesHash
		d.mu.Unlock()
	}
	return res, err
}

func ReadPolicy() (contracts.Policy, error) {
	data, err := sysio.ReadRootOwnedSmallFile(contracts.PolicyPath, contracts.MaxSmallFileBytes)
	if err != nil {
		return contracts.Policy{}, err
	}
	var p contracts.Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return contracts.Policy{}, err
	}
	if err := p.NormalizeAndValidate(); err != nil {
		return contracts.Policy{}, err
	}
	return p, nil
}

func ReadExemption(path string) (contracts.ExemptionV1, error) {
	data, err := sysio.ReadRootOwnedSmallFile(path, contracts.MaxSmallFileBytes)
	if err != nil {
		return contracts.ExemptionV1{}, err
	}
	var ex contracts.ExemptionV1
	if err := json.Unmarshal(data, &ex); err != nil {
		return contracts.ExemptionV1{}, err
	}
	return ex, nil
}

func ReadDesiredState() (contracts.DesiredState, error) {
	data, err := sysio.ReadRootOwnedSmallFile(contracts.DesiredStatePath, 1024)
	if err != nil {
		return contracts.DesiredState{}, err
	}
	var ds contracts.DesiredState
	if err := json.Unmarshal(data, &ds); err != nil {
		return contracts.DesiredState{}, err
	}
	return ds, nil
}

func SaveDesiredState(paused bool) error {
	return saveDesiredStateTo(contracts.DesiredStatePath, paused)
}

func saveDesiredStateTo(path string, paused bool) error {
	b, err := json.Marshal(contracts.DesiredState{Paused: paused})
	if err != nil {
		return err
	}
	return sysio.WriteAtomic(path, append(b, '\n'), sysio.WriteAtomicOptions{Perm: 0600, UID: 0, GID: 0})
}

func (d *Daemon) resolvedDesiredStatePath() string {
	if d.desiredStatePath != "" {
		return d.desiredStatePath
	}
	return contracts.DesiredStatePath
}

// setDesiredPaused serializes desired_state.json persistence with d.paused updates under desiredStateMu (desiredStateMu -> d.mu).
func (d *Daemon) setDesiredPaused(paused bool, bumpWakeSeq bool, ignoreDiskErr bool) (bool, contracts.Policy, error) {
	d.desiredStateMu.Lock()
	defer d.desiredStateMu.Unlock()

	if err := saveDesiredStateTo(d.resolvedDesiredStatePath(), paused); err != nil && !ignoreDiskErr {
		return false, contracts.Policy{}, err
	}
	d.mu.Lock()
	if !paused && bumpWakeSeq {
		d.wakeSeq++
	}
	d.paused = paused
	if paused {
		d.hotEscalating = false
	}
	d.kickAttempts = 0
	d.kickNextAt = time.Time{}
	loaded, policy := d.policyLoaded, d.policy
	d.mu.Unlock()
	return loaded, policy, nil
}

// tryAutoPauseDesiredState atomically checks wakeSeq/open invariants and persists desired_state.json=true without diverging from d.paused.
func (d *Daemon) tryAutoPauseDesiredState(startWakeSeq uint64) bool {
	d.desiredStateMu.Lock()
	defer d.desiredStateMu.Unlock()

	d.mu.Lock()
	if d.wakeSeq != startWakeSeq || d.paused || d.state != StateOpen || !d.policyLoaded {
		d.mu.Unlock()
		return false
	}
	d.paused = true
	d.hotEscalating = false
	d.kickAttempts = 0
	d.kickNextAt = time.Time{}
	d.mu.Unlock()

	_ = saveDesiredStateTo(d.resolvedDesiredStatePath(), true)
	return true
}

func ReadUpgradeFence(bootID string) (contracts.UpgradeFence, error) {
	data, err := sysio.ReadRootOwnedSmallFile(contracts.UpgradeFencePath, 1024)
	if err != nil {
		return contracts.UpgradeFence{}, err
	}
	var f contracts.UpgradeFence
	if err := json.Unmarshal(data, &f); err != nil {
		return contracts.UpgradeFence{}, err
	}
	if f.BootID != bootID {
		return contracts.UpgradeFence{}, errors.New("stale boot_id fence")
	}
	return f, nil
}

func (d *Daemon) readCurrentAck(policy ...contracts.Policy) *contracts.SandboxAckV1 {
	p := d.sandboxAckPath
	if p == "" {
		if len(policy) > 0 {
			p = policy[0].EffectiveProxyAckPath()
		} else {
			p = contracts.SandboxAckPath
		}
	}
	data, err := sysio.ReadRootOwnedSmallFile(p, contracts.MaxSmallFileBytes)
	if err != nil {
		return nil
	}
	ack, err := ParseSandboxAck(data, d.bootID)
	if err != nil {
		return nil
	}
	return ack
}

func (d *Daemon) writeExemption(ex contracts.ExemptionV1) error {
	p := d.exemptionPath
	if p == "" {
		p = contracts.ExemptionPath
	}
	b, err := json.Marshal(ex)
	if err != nil {
		return err
	}
	return sysio.WriteAtomic(p, append(b, '\n'), sysio.WriteAtomicOptions{Perm: 0600, UID: 0, GID: 0})
}

// RefreshBrokerAuth verifies User 0 controller base.apk signing cert against policy.json
// and writes {"allowed_user0_uid":...} atomically to broker_auth.json.
func (d *Daemon) RefreshBrokerAuth(ctx context.Context) (int, error) {
	d.mu.Lock()
	loaded := d.policyLoaded
	policy := d.policy
	d.mu.Unlock()

	authPath := d.resolvedBrokerAuthPath()
	writeOpts := d.brokerAuthWriteOpts()
	denyAuth := func(cause error) (int, error) {
		b, _ := json.Marshal(contracts.BrokerAuth{AllowedUser0UID: 0})
		_ = sysio.WriteAtomic(authPath, append(b, '\n'), writeOpts)
		return 0, cause
	}

	if !loaded {
		return denyAuth(errors.New("policy not loaded"))
	}
	uid, apkPath, err := android.DiscoverUser0Package(ctx, d.runner, policy.EffectiveCallerPackage())
	if err != nil {
		if isTransientPackageDiscoveryErr(err) && hasValidBrokerAuthUID(authPath) {
			return 0, err
		}
		return denyAuth(err)
	}
	certs, err := apkcert.ExtractAPKCertSHA256s(apkPath)
	if err != nil {
		return denyAuth(fmt.Errorf("extract cert from %s: %w", apkPath, err))
	}
	matched := false
	for _, c := range certs {
		if strings.EqualFold(c, policy.CallerCertSHA256) {
			matched = true
			break
		}
	}
	if !matched {
		return denyAuth(fmt.Errorf("caller cert mismatch on %s (got %v, want %s)", apkPath, certs, policy.CallerCertSHA256))
	}
	b, err := json.Marshal(contracts.BrokerAuth{AllowedUser0UID: uid})
	if err != nil {
		return 0, err
	}
	if err := sysio.WriteAtomic(authPath, append(b, '\n'), writeOpts); err != nil {
		return 0, err
	}
	return uid, nil
}

func isTransientPackageDiscoveryErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return !strings.Contains(msg, "UID not found") &&
		!strings.Contains(msg, "invalid User 0 UID") &&
		!strings.Contains(msg, "no APK path found")
}

func hasValidBrokerAuthUID(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > contracts.MaxSmallFileBytes {
		return false
	}
	var auth contracts.BrokerAuth
	if err := json.Unmarshal(bytes.TrimSpace(data), &auth); err != nil {
		return false
	}
	return auth.AllowedUser0UID > 0
}

func (d *Daemon) Supervise() int {
	unlock, ok, err := sysio.TryFlockNonBlocking(contracts.DaemonLockPath, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if !ok {
		return 0 // Another sandbox_guard daemon already owns supervision.
	}
	defer unlock()

	_ = os.MkdirAll(contracts.GuardHome, 0700)
	_ = sysio.WriteAtomic(filepath.Join(contracts.GuardHome, "guard.pid"), []byte(strconv.Itoa(os.Getpid())+"\n"),
		sysio.WriteAtomicOptions{Perm: 0600, UID: 0, GID: 0})
	defer os.Remove(filepath.Join(contracts.GuardHome, "guard.pid"))

	ctx, cancel := context.WithCancel(context.Background())
	d.mu.Lock()
	d.shuttingDown = false
	d.superviseCtx = ctx
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.shuttingDown = true
		mc := d.maintCancel
		d.mu.Unlock()
		if mc != nil {
			mc()
		}
		cancel()
		d.maintWg.Wait()
	}()

	// Ensure /dev directories have exact permissions & SELinux labels.
	ensureDevDirs()
	perfInit := d.getPerfConfig()
	if oomErr := ApplyOOMScoreAdj(perfInit.OOMScoreAdj); oomErr != nil {
		d.log.Printf("set oom_score_adj=%d: %v", perfInit.OOMScoreAdj, oomErr)
	}

	// Immediately enforce fail-closed gates on startup before serving IPC.
	// Skip heavy sandbox app policy sync when booting paused under hot/hybrid/deep mode so User 10 is not woken needlessly.
	syncOnBoot := !(d.isPaused() && (perfInit.PauseMode == PauseModeDeep || perfInit.PauseMode == PauseModeHybrid || perfInit.PauseMode == PauseModeHot))
	if err := d.reconcileOnce(ctx, reconcileReq{clearAckBlock: true, refreshCert: true, syncHide: syncOnBoot}); err != nil {
		d.log.Printf("initial reconcile: %v", err)
	}

	stopRPC, err := rpc.ServeGuardRPC(ctx, contracts.GuardSockPath, d)
	if err != nil {
		d.log.Printf("serve guard.sock: %v", err)
		return 1
	}
	defer stopRPC()

	stopCtl, err := rpc.ServeRootCtl(ctx, contracts.CtlSockPath, d)
	if err != nil {
		d.log.Printf("serve ctl.sock: %v", err)
		return 1
	}
	defer stopCtl()

	d.maintWg.Add(1)
	go func() {
		defer d.maintWg.Done()
		d.bootMaintain(ctx, !syncOnBoot)
	}()

	ch := WatchChannels{
		RouteWake:     make(chan struct{}, 1),
		AckWake:       make(chan struct{}, 1),
		VPNStatusWake: make(chan struct{}, 1),
		PkgWake:       make(chan struct{}, 1),
		UserWake:      make(chan struct{}, 1),
		Shutdown:      make(chan string, 1),
		Fail:          make(chan error, 4),
	}
	stopRoutes, err := WatchRoutes(ch.RouteWake, ch.Fail)
	if err != nil {
		d.log.Printf("WatchRoutes: %v", err)
		return 1
	}
	defer stopRoutes()

	ino, err := StartInotifyWatcher(ch)
	if err != nil {
		d.log.Printf("StartInotifyWatcher: %v", err)
		return 1
	}
	d.watchers = ino
	d.mu.Lock()
	cid := d.cachedID
	if d.timerRefreshCh == nil {
		d.timerRefreshCh = make(chan struct{}, 1)
	}
	timerRefresh := d.timerRefreshCh
	d.mu.Unlock()
	if cid != nil {
		pkg := contracts.DefaultWorkPackage
		d.mu.Lock()
		if d.policyLoaded {
			pkg = d.policy.EffectiveCallerPackage()
		}
		d.mu.Unlock()
		ino.EnsureWorkFilesWatch(cid.UserID, cid.ClientUID, pkg)
	}
	defer ino.Close()

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	signal.Ignore(syscall.SIGHUP)

	var routeDebounce <-chan time.Time
	var lastHint time.Time
	var lastRouteFP string
	var lastRouteFlushAt time.Time
	idleTracker := &idleAutoPauseTracker{}
	var hintT, ackT, fenceT, kickT, switchGraceT, autoPauseT, hotEscalateT *time.Timer
	var hintTimer, ackTimer, fenceTimer, kickTimer, switchGraceTimer, autoPauseTimer, hotEscalateTimer <-chan time.Time

	resetTimer := func(t **time.Timer, ch *<-chan time.Time, d time.Duration) {
		if *t != nil {
			if !(*t).Stop() {
				select {
				case <-(*t).C:
				default:
				}
			}
			(*t).Reset(d)
			*ch = (*t).C
			return
		}
		*t = time.NewTimer(d)
		*ch = (*t).C
	}
	clearTimer := func(t **time.Timer, ch *<-chan time.Time) {
		if *t != nil {
			if !(*t).Stop() {
				select {
				case <-(*t).C:
				default:
				}
			}
		}
		*ch = nil
	}
	defer func() {
		clearTimer(&hintT, &hintTimer)
		clearTimer(&ackT, &ackTimer)
		clearTimer(&fenceT, &fenceTimer)
		clearTimer(&kickT, &kickTimer)
		clearTimer(&switchGraceT, &switchGraceTimer)
		clearTimer(&autoPauseT, &autoPauseTimer)
		clearTimer(&hotEscalateT, &hotEscalateTimer)
	}()

	armTimers := func() {
		d.mu.Lock()
		ackDead := d.ackWaitDeadlineNs
		fence := d.fence
		nextKick := d.kickNextAt
		graceUntil := d.switchGraceUntilNs
		curState := d.state
		pausedNow := d.paused
		polMode := d.policy.Mode
		loadedNow := d.policyLoaded
		escalatingNow := d.hotEscalating
		d.mu.Unlock()
		perfNow := d.getPerfConfig()

		nowNs := d.nowMonoNs()
		if ackDead > 0 {
			rem := time.Duration(ackDead - nowNs)
			if rem < time.Millisecond {
				rem = time.Millisecond
			}
			resetTimer(&ackT, &ackTimer, rem)
		} else {
			clearTimer(&ackT, &ackTimer)
		}

		if FenceActive(fence, d.bootID, nowNs) {
			rem := time.Duration(fence.UntilMonoNs - nowNs)
			if rem < time.Millisecond {
				rem = time.Millisecond
			}
			resetTimer(&fenceT, &fenceTimer, rem)
		} else {
			clearTimer(&fenceT, &fenceTimer)
		}

		if !nextKick.IsZero() {
			rem := time.Until(nextKick)
			if rem < time.Millisecond {
				rem = time.Millisecond
			}
			resetTimer(&kickT, &kickTimer, rem)
		} else {
			clearTimer(&kickT, &kickTimer)
		}

		if graceUntil > 0 {
			rem := time.Duration(graceUntil - nowNs)
			if rem < time.Millisecond {
				rem = time.Millisecond
			}
			resetTimer(&switchGraceT, &switchGraceTimer, rem)
		} else {
			clearTimer(&switchGraceT, &switchGraceTimer)
		}

		if loadedNow && !pausedNow && curState == StateOpen && polMode == contracts.ModeTProxy && perfNow.AutoPauseIdleMinutes > 0 {
			if autoPauseTimer == nil {
				resetTimer(&autoPauseT, &autoPauseTimer, 60*time.Second)
			}
		} else {
			idleTracker.Reset()
			clearTimer(&autoPauseT, &autoPauseTimer)
		}

		if loadedNow && pausedNow && !escalatingNow && polMode == contracts.ModeTProxy && perfNow.HotFreezeMinutes > 0 &&
			android.ReadHibernatedState(d.resolvedHibernatedPath()).HotFrozen {
			if hotEscalateTimer == nil {
				resetTimer(&hotEscalateT, &hotEscalateTimer, time.Duration(perfNow.HotFreezeMinutes)*time.Minute)
			}
		} else {
			clearTimer(&hotEscalateT, &hotEscalateTimer)
		}
	}
	armTimers()

	for {
		select {
		case sig := <-signals:
			d.log.Printf("signal %v", sig)
			d.closeGatesOnShutdown(ctx)
			return 0
		case why := <-ch.Shutdown:
			d.log.Printf("shutdown trigger: %s", why)
			d.closeGatesOnShutdown(ctx)
			return 0
		case err := <-ch.Fail:
			d.log.Printf("watcher fail: %v", err)
			return 1
		case <-ch.RouteWake:
			if routeDebounce == nil {
				routeDebounce = time.After(25 * time.Millisecond)
			}
		case <-routeDebounce:
			routeDebounce = nil
			_ = d.reconcileOnce(ctx, reconcileReq{})
			d.maybeFlushOnRouteChange(ctx, &lastRouteFP, &lastRouteFlushAt)
			armTimers()
		case <-ch.AckWake:
			_ = d.reconcileOnce(ctx, reconcileReq{clearAckBlock: true})
			armTimers()
		case <-ch.VPNStatusWake:
			elapsed := time.Since(lastHint)
			if elapsed >= 100*time.Millisecond || d.shouldBypassHintThrottle() {
				clearTimer(&hintT, &hintTimer)
				lastHint = time.Now()
				_ = d.reconcileOnce(ctx, reconcileReq{hintHandoff: true})
				armTimers()
			} else if hintTimer == nil {
				resetTimer(&hintT, &hintTimer, 100*time.Millisecond-elapsed)
			}
		case <-hintTimer:
			hintTimer = nil
			lastHint = time.Now()
			_ = d.reconcileOnce(ctx, reconcileReq{hintHandoff: true})
			armTimers()
		case <-switchGraceTimer:
			switchGraceTimer = nil
			_ = d.reconcileOnce(ctx, reconcileReq{})
			armTimers()
		case <-ch.PkgWake:
			d.invalidateLaunchCaches()
			_ = d.reconcileOnce(ctx, reconcileReq{invalidateID: true, refreshCert: true, syncHide: !d.isPaused()})
			armTimers()
		case <-ch.UserWake:
			d.mu.Lock()
			d.userUnlockedBoot = false
			d.mu.Unlock()
			if d.isPaused() {
				_ = d.reconcileOnce(ctx, reconcileReq{})
				pm := d.getPerfConfig().PauseMode
				if pm == PauseModeDeep || pm == PauseModeHybrid || pm == PauseModeHot {
					d.mu.Lock()
					due := d.lastBootPauseEnforceAt.IsZero() || time.Since(d.lastBootPauseEnforceAt) >= 10*time.Second
					d.mu.Unlock()
					if due {
						d.maintWg.Add(1)
						go func() {
							defer d.maintWg.Done()
							d.enforcePausedAtBootLocked(ctx)
						}()
					}
				}
			} else {
				_ = d.reconcileOnce(ctx, reconcileReq{invalidateID: true, clearAckBlock: true})
			}
			armTimers()
		case <-ackTimer:
			ackTimer = nil
			_ = d.reconcileOnce(ctx, reconcileReq{})
			armTimers()
		case <-fenceTimer:
			fenceTimer = nil
			_ = d.reconcileOnce(ctx, reconcileReq{clearAckBlock: true})
			armTimers()
		case <-kickTimer:
			kickTimer = nil
			d.handleRecoveryKick(ctx)
			armTimers()
		case <-autoPauseTimer:
			autoPauseTimer = nil
			d.stepAutoPauseCheck(ctx, idleTracker)
			armTimers()
		case <-hotEscalateTimer:
			hotEscalateTimer = nil
			d.mu.Lock()
			loadedEsc, pausedEsc, polEsc := d.policyLoaded, d.paused, d.policy
			d.mu.Unlock()
			hotFrozen := loadedEsc && pausedEsc && polEsc.IsTProxy() && android.ReadHibernatedState(d.resolvedHibernatedPath()).HotFrozen
			canEscalate := false
			if hotFrozen {
				d.mu.Lock()
				if d.policyLoaded && d.paused && !d.hotEscalating && d.policy.IsTProxy() {
					d.hotEscalating = true
					polEsc = d.policy
					canEscalate = true
				}
				d.mu.Unlock()
			}
			if canEscalate {
				d.log.Printf("escalating L1 hot-frozen sandbox (user=%d) to L2 deep hibernation after idle timeout", polEsc.UserID)
				d.dispatchAsyncPauseMaintenance(ctx, polEsc, PauseModeDeep)
			}
			armTimers()
		case <-timerRefresh:
			armTimers()
		case req := <-d.reconcileCh:
			err := d.reconcileOnce(ctx, req)
			armTimers()
			if req.reply != nil {
				req.reply <- err
			}
		}
	}
}

func (d *Daemon) notifyTimerRefresh() {
	d.mu.Lock()
	ch := d.timerRefreshCh
	d.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (d *Daemon) requestReconcile(ctx context.Context, req reconcileReq) error {
	req.reply = make(chan error, 1)
	select {
	case d.reconcileCh <- req:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-req.reply:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Daemon) reconcileOnce(ctx context.Context, req reconcileReq) error {
	if req.refreshCert {
		if _, err := d.RefreshBrokerAuth(ctx); err != nil {
			d.log.Printf("broker_auth refresh: %v", err)
		}
	}

	d.mu.Lock()
	if req.clearAckBlock {
		d.ackWaitBlocked = false
	}
	if req.invalidateID {
		d.cachedID = nil
	}
	if !d.policyLoaded {
		if p, err := ReadPolicy(); err == nil {
			d.policy = p
			d.policyLoaded = true
		}
	}
	loaded := d.policyLoaded
	policy := d.policy
	paused := d.paused
	cachedID := d.cachedID
	fence := d.fence
	curEx := d.currentExemption
	lastGen := d.lastGen
	curState := d.state
	ackDead := d.ackWaitDeadlineNs
	ackBlocked := d.ackWaitBlocked
	lastSess := d.lastSession
	graceUntil := d.switchGraceUntilNs
	d.mu.Unlock()

	if !loaded {
		d.mu.Lock()
		d.state = StateBlockedBoot
		d.switchGraceUntilNs = 0
		d.lastError = "policy.json not pinned"
		d.mu.Unlock()
		return nil
	}

	if req.syncHide {
		if _, err := android.SyncHideApps(ctx, d.runner, policy.UserID, policy.Serial); err != nil {
			d.log.Printf("sync hide apps: %v", err)
		}
		if _, err := d.syncPolicies(ctx, policy); err != nil {
			d.log.Printf("sync sandbox app policies: %v", err)
		}
	}

	// Verify static profile identity (boot-cached unless invalidated or not yet verified).
	var id android.VerifiedIdentity
	identityOK := false
	if cachedID != nil {
		id = *cachedID
		identityOK = true
		if req.syncHide && (d.stealthConfigPath != "" || runtime.GOOS == "linux") {
			if _, serr := d.SyncStealthConfig(policy, id.ClientUID); serr != nil {
				d.log.Printf("sync stealth config: %v", serr)
			}
		}
	} else {
		if verified, err := android.VerifyStaticIdentity(ctx, d.runner, policy); err == nil {
			id = verified
			identityOK = true
			d.mu.Lock()
			d.cachedID = &verified
			d.mu.Unlock()
			if d.watchers != nil {
				d.watchers.EnsureWorkFilesWatch(verified.UserID, verified.ClientUID, policy.EffectiveCallerPackage())
			}
			_ = android.EnsureWorkPermissions(ctx, d.runner, verified.UserID, policy.EffectiveCallerPackage())
			if d.stealthConfigPath != "" || runtime.GOOS == "linux" {
				if _, serr := d.SyncStealthConfig(policy, verified.ClientUID); serr != nil {
					d.log.Printf("sync stealth config: %v", serr)
				}
			}
		} else {
			d.mu.Lock()
			d.lastError = err.Error()
			d.mu.Unlock()
		}
	}

	// Read vpn_status.json safely via SafeResolver (never setresuid). Not used in TProxy mode (no TunService).
	isTProxy := policy.IsTProxy()
	callerPkg := policy.EffectiveCallerPackage()
	var vpnStatus *contracts.VPNStatus
	if identityOK && !isTProxy {
		if st, err := d.readWorkVPNStatus(id.UserID, id.ClientUID, callerPkg); err == nil {
			vpnStatus = st
		}
	}

	// TProxy mode: proxy core alive + listening on tproxy port (pure Go, zero fork).
	tproxyReady := false
	if isTProxy && identityOK {
		tproxyReady = d.tproxyReady(policy)
	}

	// Discover active VPN session (zero-dumpsys fast path via vpn_status.json + net.InterfaceByName).
	var sess *netfilter.ActiveSession
	var sessionErr error
	if identityOK && !isTProxy && !paused && !FenceActive(fence, d.bootID, d.nowMonoNs()) {
		if fastSess, ok := d.resolveFastSession(d.bootID, id.ClientUID, vpnStatus); ok {
			sess = fastSess
		} else {
			verifyRoutes := curState != StateOpen
			sess, sessionErr = android.DiscoverSessionFromConnectivity(ctx, d.runner, id, verifyRoutes, policy.EndpointV4, policy.PortalDNS4)
		}
	}

	nowNs := d.nowMonoNs()
	inGrace := false
	nextGraceUntil := int64(0)
	if sess == nil && identityOK && !isTProxy && !paused && !FenceActive(fence, d.bootID, nowNs) &&
		curState == StateOpen && curEx != nil && curEx.State == "open" && lastSess != nil {
		explicitStop := vpnStatus != nil && (!vpnStatus.Running || (vpnStatus.BootID != "" && vpnStatus.BootID != d.bootID))
		if !explicitStop && d.isTunAlive(curEx.TunIf, curEx.TunIfindex) && d.isWorkServiceAlive(id.ClientUID, callerPkg) {
			deadline := graceUntil
			if deadline == 0 {
				deadline = nowNs + SwitchoverGraceNs
			}
			if nowNs < deadline {
				inGrace = true
				nextGraceUntil = deadline
				sess = lastSess
				sessionErr = nil
				if graceUntil == 0 && d.log != nil {
					d.log.Printf("switchover grace active (tun=%s idx=%d alive); holding StateOpen up to %dms",
						curEx.TunIf, curEx.TunIfindex, SwitchoverGraceNs/1_000_000)
				}
			}
		}
	}

	// OEM/kernel cgroup freeze check if session missing (and NOT inside active switchover grace).
	if sess == nil && identityOK && !isTProxy && !paused && !FenceActive(fence, d.bootID, nowNs) && !inGrace {
		if pid, alive, _ := android.FindWorkServicePID(id.ClientUID, callerPkg); alive {
			fs := inspectAnyFreeze(id.ClientUID, pid)
			if fs.Frozen {
				d.log.Printf("cgroup freeze detected on pid %d (%s); unfreezing", pid, fs.Evidence)
				_ = android.EnsureWorkPermissions(ctx, d.runner, id.UserID, callerPkg)
				_ = unfreezeAny(id.ClientUID, pid, fs)
				if s2, e2 := android.DiscoverSessionFromConnectivity(ctx, d.runner, id, true, policy.EndpointV4, policy.PortalDNS4); e2 == nil {
					sess = s2
					sessionErr = nil
				}
			}
		}
	}

	extCap, err := d.nf.DetectProxyCapture(ctx, policy.ProxySkipPrefix)
	if err != nil {
		d.log.Printf("detect proxy capture: %v", err)
		if policy.ProxySkipPrefix != "" {
			extCap = true // fail-closed when external proxy capture prefix is configured
		}
	}
	ack := d.readCurrentAck(policy)
	nowNs = d.nowMonoNs()

	in := EvalInput{
		BootID:            d.bootID,
		NowMonoNs:         nowNs,
		PolicyLoaded:      loaded,
		Policy:            policy,
		KnownClientUID:    id.ClientUID,
		Paused:            paused,
		Fence:             fence,
		IdentityOK:        identityOK,
		LGPPresent:        extCap,
		Session:           sess,
		Ack:               ack,
		CurrentExemption:  curEx,
		LastGeneration:    lastGen,
		AckWaitDeadlineNs: ackDead,
		AckWaitBlocked:    ackBlocked,
		TProxyReady:       tproxyReady,
	}
	dec := Evaluate(in)

	// Persist exemption.v1.json if changed.
	if dec.WriteExemption {
		if err := d.writeExemption(dec.NewExemption); err != nil {
			d.log.Printf("write exemption.v1.json: %v", err)
			// Fail closed if exemption could not be persisted.
			dec.OpenGate = false
			dec.ArmRawDrop = extCap
			dec.NextState = StateBlockedLocked
		} else {
			d.mu.Lock()
			exCopy := dec.NewExemption
			d.currentExemption = &exCopy
			if dec.NewExemption.Generation > d.lastGen {
				d.lastGen = dec.NewExemption.Generation
			}
			d.mu.Unlock()
		}
	}

	// Build and atomically apply Netfilter chains under shared flock.
	uidStart, uidEnd := policy.UIDRange()
	lastVPNNetID := 0
	if curEx != nil && curEx.VPNNetID > 0 {
		lastVPNNetID = curEx.VPNNetID
	}
	if sess != nil && sess.VPNNetID > 0 {
		lastVPNNetID = sess.VPNNetID
	}
	perf := d.getPerfConfig()
	pendingMap := d.resolvePendingConfig(loaded, policy, vpnStatus)
	quicReject := perf.KernelRejectQuicUDP443
	if qm, ok := pendingMap["quic_udp443_mode"].(string); ok && qm == "allow" {
		quicReject = false
	}
	gateSpec := netfilter.GateSpec{
		UserID:                 policy.UserID,
		UIDStart:               uidStart,
		UIDEnd:                 uidEnd,
		PortalDNS4:             policy.PortalDNS4,
		EndpointV4:             policy.EndpointV4,
		EndpointPort:           policy.EndpointPort,
		IPv6Enabled:            policy.IPv6Enabled,
		ArmRawDrop:             dec.ArmRawDrop,
		Open:                   dec.OpenGate,
		Session:                sess,
		LastVPNNetID:           lastVPNNetID,
		Mode:                   policy.Mode,
		TProxyPort:             policy.TProxyPort,
		TProxyMark:             policy.TProxyMark,
		ProxySkipPrefix:        policy.ProxySkipPrefix,
		KernelRejectQuicUDP443: quicReject,
	}

	if err := d.nf.ApplyOrVerify(ctx, gateSpec, false); err != nil {
		if d.log != nil {
			d.log.Printf("netfilter apply failed: %v", err)
		}
		// Attempt safe closed gate fallback (preserving RawDrop arming if external proxy capture is active).
		gateSpec.Open = false
		gateSpec.Session = nil
		gateSpec.ArmRawDrop = extCap
		_ = d.nf.ApplyOrVerify(ctx, gateSpec, false)
		dec.NextState = StateBlockedLocked
		dec.OpenGate = false
		dec.ArmRawDrop = extCap

		if (dec.WriteExemption && dec.NewExemption.State == "open") || (curEx != nil && curEx.State == "open") {
			nextGen := lastGen
			if dec.NewExemption.Generation > nextGen {
				nextGen = dec.NewExemption.Generation
			}
			nextGen++
			blockedEx := BuildBlockedExemption(policy, d.bootID, id.ClientUID, nextGen)
			if werr := d.writeExemption(blockedEx); werr == nil {
				d.mu.Lock()
				exCopy := blockedEx
				d.currentExemption = &exCopy
				if blockedEx.Generation > d.lastGen {
					d.lastGen = blockedEx.Generation
				}
				d.mu.Unlock()
			}
		}

		d.mu.Lock()
		d.lastError = err.Error()
		d.mu.Unlock()
	}

	// Update daemon runtime fields and bounded recovery schedule.
	d.mu.Lock()
	d.state = dec.NextState
	d.lastRawArmed = dec.ArmRawDrop
	d.lastOpen = dec.OpenGate
	d.lastSession = sess
	d.lastVPNStatus = vpnStatus
	d.lastAppliedSpec = &gateSpec
	if dec.NextState == StateOpen && inGrace {
		d.switchGraceUntilNs = nextGraceUntil
	} else {
		d.switchGraceUntilNs = 0
	}
	if dec.ClearFence {
		d.fence = contracts.UpgradeFence{}
		_ = os.Remove(contracts.UpgradeFencePath)
	}
	if dec.StartAckWait {
		d.ackWaitDeadlineNs = nowNs + AckWaitTimeoutNs
	} else if dec.ClearAckDeadline {
		d.ackWaitDeadlineNs = 0
	}
	if dec.AckTimedOut {
		d.ackWaitBlocked = true
	}
	if dec.OpenGate {
		d.kickAttempts = 0
		d.kickNextAt = time.Time{}
		d.lastError = ""
	} else if !paused && identityOK && errors.Is(sessionErr, android.ErrWorkVPNMissing) && !FenceActive(d.fence, d.bootID, nowNs) {
		// Bounded recovery backoff ONLY when work VPN is missing while desired.
		delays := []time.Duration{2 * time.Second, 7 * time.Second, 16 * time.Second}
		if d.kickAttempts < len(delays) && d.kickNextAt.IsZero() {
			d.kickNextAt = time.Now().Add(delays[d.kickAttempts])
		}
	} else if !errors.Is(sessionErr, android.ErrWorkVPNMissing) {
		d.kickAttempts = 0
		d.kickNextAt = time.Time{}
	}
	d.mu.Unlock()
	return nil
}

func inspectAnyFreeze(clientUID, pid int) android.FreezeState {
	fs := android.InspectCgroupV2Freeze(nil, clientUID, pid)
	if !fs.Frozen {
		if v1 := android.InspectCgroupV1Freeze(nil, clientUID, pid); v1.Frozen {
			return v1
		}
	}
	return fs
}

func unfreezeAny(clientUID, pid int, fs android.FreezeState) error {
	if strings.Contains(fs.FreezePath, "/freezer/") || strings.Contains(fs.Evidence, "/freezer/") {
		return android.UnfreezeCgroupV1(nil, clientUID, pid, fs)
	}
	return android.UnfreezeCgroupV2(nil, clientUID, pid, fs)
}

func (d *Daemon) closeGatesOnShutdown(ctx context.Context) {
	d.mu.Lock()
	loaded, policy, gen := d.policyLoaded, d.policy, d.lastGen
	d.mu.Unlock()
	if !loaded {
		return
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ex := BuildBlockedExemption(policy, d.bootID, 0, gen+1)
	_ = d.writeExemption(ex)
	extCap, _ := d.nf.DetectProxyCapture(sctx, policy.ProxySkipPrefix)
	spec := closedGateSpec(policy, extCap)
	_ = d.nf.ApplyOrVerify(sctx, spec, false)
	_ = ctx
}

// closedGateSpec builds a fail-closed GateSpec (Open=false) honoring the pinned policy mode.
func closedGateSpec(p contracts.Policy, armRaw bool) netfilter.GateSpec {
	uidStart, uidEnd := p.UIDRange()
	return netfilter.GateSpec{
		UserID: p.UserID, UIDStart: uidStart, UIDEnd: uidEnd,
		PortalDNS4: p.PortalDNS4, EndpointV4: p.EndpointV4, EndpointPort: p.EndpointPort,
		IPv6Enabled: p.IPv6Enabled, ArmRawDrop: armRaw, Open: false,
		Mode: p.Mode, TProxyPort: p.TProxyPort, TProxyMark: p.TProxyMark,
		ProxySkipPrefix: p.ProxySkipPrefix,
	}
}

func (d *Daemon) handleRecoveryKick(ctx context.Context) {
	d.mu.Lock()
	d.kickNextAt = time.Time{}
	if d.paused || !d.policyLoaded || d.cachedID == nil || FenceActive(d.fence, d.bootID, sysio.MonotonicNowNs()) {
		d.kickAttempts = 0
		d.mu.Unlock()
		return
	}
	id := *d.cachedID
	attempt := d.kickAttempts
	policy := d.policy
	d.mu.Unlock()

	// Re-verify profile/lockdown/package state before starting TunService.
	verified, err := android.VerifyStaticIdentity(ctx, d.runner, policy)
	if err != nil {
		d.mu.Lock()
		d.cachedID = nil
		d.lastError = err.Error()
		d.mu.Unlock()
		return
	}
	callerPkg := policy.EffectiveCallerPackage()
	pkgs, err := d.runner.Run(ctx, 4*time.Second, "", "dumpsys", "package", callerPkg)
	if err != nil || !android.WorkPackageCanRun(pkgs, verified.UserID) {
		return
	}
	pid, running, _ := android.FindWorkServicePID(verified.ClientUID, callerPkg)
	if running {
		fs := inspectAnyFreeze(verified.ClientUID, pid)
		if fs.Frozen {
			_ = android.EnsureWorkPermissions(ctx, d.runner, verified.UserID, callerPkg)
			_ = unfreezeAny(verified.ClientUID, pid, fs)
		}
		return
	}

	_ = android.EnsureWorkPermissions(ctx, d.runner, verified.UserID, callerPkg)
	_, err = d.runner.Run(ctx, 5*time.Second, "", "am", "start-foreground-service",
		"--user", strconv.Itoa(id.UserID),
		"-a", callerPkg+".action.START_VPN",
		"-n", policy.EffectiveServiceComponent())
	if err != nil {
		d.log.Printf("recovery start TunService failed: %v", err)
	}

	d.mu.Lock()
	d.kickAttempts = attempt + 1
	delays := []time.Duration{2 * time.Second, 7 * time.Second, 16 * time.Second}
	if d.kickAttempts < len(delays) && !d.paused {
		d.kickNextAt = time.Now().Add(delays[d.kickAttempts])
	}
	d.mu.Unlock()
}

func (d *Daemon) readWorkVPNStatus(userID, clientUID int, workPkg string) (*contracts.VPNStatus, error) {
	data, err := sysio.ReadWorkVPNStatusBytes(d.resolver, userID, clientUID, workPkg)
	if err != nil {
		return nil, err
	}
	var st contracts.VPNStatus
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (d *Daemon) nowMonoNs() int64 {
	if d.nowMonoNsFn != nil {
		return d.nowMonoNsFn()
	}
	return sysio.MonotonicNowNs()
}

func (d *Daemon) resolveFastSession(bootID string, clientUID int, status *contracts.VPNStatus) (*netfilter.ActiveSession, bool) {
	if d.probeFastSession != nil {
		return d.probeFastSession(bootID, clientUID, status)
	}
	return android.ResolveFastStatusSession(bootID, clientUID, status)
}

func (d *Daemon) isTunAlive(tunIf string, expectedIfindex int) bool {
	if d.probeTunAlive != nil {
		return d.probeTunAlive(tunIf, expectedIfindex)
	}
	ifc, ok := android.VerifyLiveIfaceUpIPv4(tunIf, true)
	if !ok {
		return false
	}
	return expectedIfindex <= 0 || ifc.Index == expectedIfindex
}

func (d *Daemon) isWorkServiceAlive(clientUID int, workPkg ...string) bool {
	if d.probeServiceAlive != nil {
		return d.probeServiceAlive(clientUID)
	}
	pkg := ""
	if len(workPkg) > 0 {
		pkg = workPkg[0]
	}
	_, alive, _ := android.FindWorkServicePID(clientUID, pkg)
	return alive
}

// shouldBypassHintThrottle checks whether vpn_status.json carries a valid running underlay
// (underlay_if, underlay_net_id) that differs from the currently applied session.
func (d *Daemon) shouldBypassHintThrottle() bool {
	d.mu.Lock()
	id := d.cachedID
	curSess := d.lastSession
	curSt := d.lastVPNStatus
	callerPkg := d.policy.EffectiveCallerPackage()
	d.mu.Unlock()
	if id == nil {
		return false
	}
	st, err := d.readWorkVPNStatus(id.UserID, id.ClientUID, callerPkg)
	if err != nil || st == nil || !st.Running || st.BootID != d.bootID {
		return false
	}
	if st.UnderlayIf == "" || st.UnderlayIf == st.TunIf || st.UnderlayIf == "lo" ||
		!contracts.UplinkIfRegex.MatchString(st.UnderlayIf) || st.UnderlayNetID < 100 {
		return false
	}
	if curSess != nil {
		return st.UnderlayIf != curSess.UplinkIf || st.UnderlayNetID != curSess.UplinkNetID
	}
	if curSt != nil {
		return st.UnderlayIf != curSt.UnderlayIf || st.UnderlayNetID != curSt.UnderlayNetID
	}
	return true
}

func (d *Daemon) ensureProxyTProxy(ctx context.Context, policy contracts.Policy) bool {
	if d.tproxyReady(policy) {
		return true
	}
	script := policy.ProxyCtlScript
	if script == "" {
		script = d.proxyCtlScript
	}
	if script == "" && runtime.GOOS == "linux" {
		script = policy.EffectiveProxyCtlScript()
	}
	if script == "" || d.runner == nil {
		return false
	}
	st, err := os.Stat(script)
	if err != nil || st.IsDir() {
		return false
	}
	if _, rerr := d.runner.Run(ctx, 10*time.Second, "", "sh", script, "start"); rerr != nil {
		d.log.Printf("auto-start external proxy (%s start): %v", script, rerr)
	}
	deadline := time.Now().Add(6 * time.Second)
	for {
		if d.tproxyReady(policy) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(150 * time.Millisecond):
		}
	}
}

type idleAutoPauseTracker struct {
	idleMinutes       int
	haveTrafficSample bool
	lastTrafficBytes  uint64
}

func (t *idleAutoPauseTracker) Reset() {
	t.idleMinutes = 0
	t.haveTrafficSample = false
	t.lastTrafficBytes = 0
}

func (t *idleAutoPauseTracker) Observe(snap android.SandboxActivitySnapshot, thresholdMinutes int) bool {
	if thresholdMinutes <= 0 {
		t.Reset()
		return false
	}
	if !t.haveTrafficSample {
		// Initialize byte baseline on first tick without falsely counting a full idle minute.
		t.lastTrafficBytes = snap.TrafficBytes
		t.haveTrafficSample = true
		t.idleMinutes = 0
		return false
	}
	var delta uint64
	if snap.TrafficBytes >= t.lastTrafficBytes {
		delta = snap.TrafficBytes - t.lastTrafficBytes
	} else {
		// iptables chain counters reset (flush/re-apply): treat current counter as post-reset transfer.
		delta = snap.TrafficBytes
	}
	t.lastTrafficBytes = snap.TrafficBytes

	// Triple gate: active window OR active audio OR >32 KiB transfer in 60s keeps sandbox awake.
	if snap.ForegroundUser || snap.AudioActive || delta > 32768 {
		t.idleMinutes = 0
		return false
	}
	t.idleMinutes++
	return t.idleMinutes >= thresholdMinutes
}

func (d *Daemon) stepAutoPauseCheck(ctx context.Context, tracker *idleAutoPauseTracker) {
	d.mu.Lock()
	loaded, paused, state, policy, startWakeSeq := d.policyLoaded, d.paused, d.state, d.policy, d.wakeSeq
	d.mu.Unlock()
	if !loaded || paused || state != StateOpen || !policy.IsTProxy() {
		tracker.Reset()
		return
	}
	perf := d.getPerfConfig()
	if perf.AutoPauseIdleMinutes <= 0 {
		tracker.Reset()
		return
	}
	snap, err := android.InspectSandboxActivityFast(ctx, d.runner, policy.UserID, d.cgroupRoot, d.asoundRoot, tracker.lastTrafficBytes, tracker.haveTrafficSample)
	if err != nil {
		return
	}
	if !tracker.Observe(snap, perf.AutoPauseIdleMinutes) {
		return
	}
	d.mu.Lock()
	if d.wakeSeq != startWakeSeq || d.paused || d.state != StateOpen || !d.policyLoaded {
		d.mu.Unlock()
		tracker.Reset()
		return
	}
	policy = d.policy
	loaded = d.policyLoaded
	d.mu.Unlock()

	targetMode := d.resolveEffectivePauseMode(perf.PauseMode, "")
	d.log.Printf("auto-pausing idle sandbox after %dm inactivity (user=%d mode=%s)", perf.AutoPauseIdleMinutes, policy.UserID, targetMode)
	if !d.tryAutoPauseDesiredState(startWakeSeq) {
		tracker.Reset()
		return
	}
	tracker.Reset()
	// Close kernel gates synchronously (fail-closed) on Supervise, then run hibernation asynchronously
	// under maintWg so Supervise never stalls waiting on d.lifecycleMu.
	_ = d.reconcileOnce(ctx, reconcileReq{clearAckBlock: true})
	d.dispatchAsyncPauseMaintenance(ctx, policy, targetMode)
}

func normalizeRouteGetFingerprint(out string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	cleaned := make([]string, 0, len(fields))
	for i := 0; i < len(fields); i++ {
		if fields[i] == "uid" && i+1 < len(fields) {
			i++
			continue
		}
		cleaned = append(cleaned, fields[i])
	}
	return strings.Join(cleaned, " ")
}

func (d *Daemon) sampleDefaultRouteFingerprint(ctx context.Context) string {
	out, err := d.runner.Run(ctx, 2*time.Second, "", "ip", "-4", "route", "get", "1.1.1.1")
	if err != nil {
		return ""
	}
	return normalizeRouteGetFingerprint(out)
}

func (d *Daemon) maybeFlushOnRouteChange(ctx context.Context, lastFP *string, lastFlush *time.Time) {
	d.mu.Lock()
	loaded, paused, state, policy := d.policyLoaded, d.paused, d.state, d.policy
	d.mu.Unlock()
	if !loaded || paused || state != StateOpen || !policy.IsTProxy() {
		return
	}
	perf := d.getPerfConfig()
	if !perf.FlushSandboxConnsOnRouteChg {
		return
	}
	fp := d.sampleDefaultRouteFingerprint(ctx)
	if fp == "" {
		return
	}
	prev := *lastFP
	*lastFP = fp
	if prev != "" && fp != prev && time.Since(*lastFlush) >= 2*time.Second {
		*lastFlush = time.Now()
		cfgPath := d.resolvedMainConfigPath(policy)
		inbound := d.resolvedInboundName(perf, policy)
		go func() {
			if n, err := FlushSandboxConnections(ctx, cfgPath, inbound); err == nil && n > 0 {
				d.log.Printf("flushed %d stale %s connections on uplink route change", n, inbound)
			}
		}()
	}
}

func (d *Daemon) bootMaintain(ctx context.Context, enforceDeepPause bool) {
	for i := 0; i < 20; i++ {
		if out, err := d.runner.Run(ctx, 2*time.Second, "", "getprop", "sys.boot_completed"); err == nil && strings.TrimSpace(out) == "1" {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Second):
		}
	}
	if enforceDeepPause {
		d.enforcePausedAtBootLocked(ctx)
	} else if !d.isPaused() {
		d.mu.Lock()
		loaded, pol := d.policyLoaded, d.policy
		d.mu.Unlock()
		if loaded && pol.IsTProxy() {
			_, _ = android.RestoreHibernatedSandboxUserWithOpts(ctx, d.runner, pol.UserID, d.resolvedHibernatedPath(), d.cgroupRoot)
		}
		d.maybePruneBloatOnBoot(ctx)
	}
	authPath := d.resolvedBrokerAuthPath()
	if !hasValidBrokerAuthUID(authPath) {
		for i := 0; i < 10; i++ {
			if uid, err := d.RefreshBrokerAuth(ctx); err == nil && uid > 0 {
				d.log.Printf("broker_auth ready after boot (uid=%d)", uid)
				return
			}
			if i == 9 {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		}
	}
}

func (d *Daemon) maybePruneBloatOnBoot(ctx context.Context) {
	perf := d.getPerfConfig()
	if !perf.AutoPruneBloatOnStart {
		return
	}
	d.mu.Lock()
	loaded, policy, alreadyPruned := d.policyLoaded, d.policy, d.bloatPrunedOnce
	d.mu.Unlock()
	if !loaded || !policy.IsTProxy() || alreadyPruned || d.isPaused() {
		return
	}
	ready := false
	for attempt := 0; attempt < 4; attempt++ {
		if d.isPaused() {
			return
		}
		if uOut, err := d.runner.Run(ctx, 3*time.Second, "", "dumpsys", "activity", "users"); err == nil {
			if android.ParseUserStateFromActivityUsers(uOut, policy.UserID) == "RUNNING_UNLOCKED" {
				ready = true
				break
			}
		}
		if attempt < 3 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	}
	if !ready {
		return
	}
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()
	if d.isPaused() {
		return
	}
	d.mu.Lock()
	stillNeed := !d.bloatPrunedOnce
	d.mu.Unlock()
	if !stillNeed {
		return
	}
	if res, perr := android.PruneSandboxBloat(ctx, d.runner, policy.UserID, d.resolvedPrunedPath(), policy.EffectiveCallerPackage()); perr == nil {
		d.mu.Lock()
		d.bloatPrunedOnce = true
		d.mu.Unlock()
		if len(res.Packages) > 0 {
			d.log.Printf("pruned %d %s bloat packages in user %d on boot", len(res.Packages), oem.Current().Name, policy.UserID)
		}
	}
}

func (d *Daemon) enforcePausedAtBootLocked(ctx context.Context) {
	d.lifecycleMu.Lock()
	defer d.lifecycleMu.Unlock()
	if !d.isPaused() {
		return
	}
	d.mu.Lock()
	loaded, policy := d.policyLoaded, d.policy
	d.mu.Unlock()
	if !loaded {
		return
	}
	perf := d.getPerfConfig()
	effMode := d.resolveEffectivePauseMode(perf.PauseMode, "")
	if effMode != PauseModeDeep && effMode != PauseModeHot {
		return
	}
	if uOut, err := d.runner.Run(ctx, 3*time.Second, "", "dumpsys", "activity", "users"); err == nil {
		if st := android.ParseUserStateFromActivityUsers(uOut, policy.UserID); st == "RUNNING_UNLOCKED" {
			d.mu.Lock()
			d.lastBootPauseEnforceAt = time.Now()
			d.mu.Unlock()
			pkgList := contracts.PackagesListPath
			if d.packagesListPath != "" {
				pkgList = d.packagesListPath
			}
			if effMode == PauseModeHot {
				if frozen, serr := android.HotFreezeSandboxUserWithOpts(ctx, d.runner, policy.UserID, d.resolvedHibernatedPath(), pkgList, d.cgroupRoot, policy.EffectiveCallerPackage()); serr == nil {
					d.log.Printf("enforced boot hot-freeze on user %d (%d UIDs frozen)", policy.UserID, frozen)
					d.notifyTimerRefresh()
				} else {
					lifeOpts := android.LifecycleOptions{
						CallerPackage:       policy.EffectiveCallerPackage(),
						PackagesListPath:    pkgList,
						CgroupRoot:          d.cgroupRoot,
						SkipAppOpsForFrozen: perf.SkipAppOpsForFrozen,
					}
					if hibernated, herr := android.HibernateSandboxUserEx(ctx, d.runner, policy.UserID, d.resolvedHibernatedPath(), lifeOpts); herr == nil {
						d.log.Printf("boot hot-freeze unavailable (%v); enforced deep hibernation on user %d (%d apps hibernated)", serr, policy.UserID, hibernated)
					}
				}
			} else {
				lifeOpts := android.LifecycleOptions{
					CallerPackage:       policy.EffectiveCallerPackage(),
					PackagesListPath:    pkgList,
					CgroupRoot:          d.cgroupRoot,
					SkipAppOpsForFrozen: perf.SkipAppOpsForFrozen,
				}
				if hibernated, serr := android.HibernateSandboxUserEx(ctx, d.runner, policy.UserID, d.resolvedHibernatedPath(), lifeOpts); serr == nil {
					d.log.Printf("enforced boot deep hibernation on user %d (%d apps hibernated, FBE key kept unlocked)", policy.UserID, hibernated)
				}
			}
		}
	}
}

func (d *Daemon) scheduleMaintenance(policy contracts.Policy, restoreRemaining bool) {
	perf := d.getPerfConfig()
	d.mu.Lock()
	if d.shuttingDown {
		d.mu.Unlock()
		return
	}
	needPrune := perf.AutoPruneBloatOnStart && !d.bloatPrunedOnce
	needSync := d.lastPolicySyncHash == ""
	if !restoreRemaining && !needPrune && !needSync {
		d.mu.Unlock()
		return
	}
	prevCancel := d.maintCancel
	baseCtx := d.superviseCtx
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	mctx, mcancel := context.WithTimeout(baseCtx, 25*time.Second)
	d.maintCancel = mcancel
	d.maintWg.Add(1)
	d.mu.Unlock()
	if prevCancel != nil {
		prevCancel()
	}
	go func(ctxBg context.Context, cancelFn context.CancelFunc, pol contracts.Policy, doRestore, doPrune, doSync bool) {
		defer d.maintWg.Done()
		defer cancelFn()
		d.lifecycleMu.Lock()
		defer d.lifecycleMu.Unlock()
		if ctxBg.Err() != nil || d.isPaused() {
			return
		}
		if doRestore {
			_, _ = android.RestoreHibernatedSandboxUserWithOpts(ctxBg, d.runner, pol.UserID, d.resolvedHibernatedPath(), d.cgroupRoot)
		}
		if ctxBg.Err() != nil || d.isPaused() {
			return
		}
		if doPrune {
			if res, perr := android.PruneSandboxBloat(ctxBg, d.runner, pol.UserID, d.resolvedPrunedPath(), pol.EffectiveCallerPackage()); perr == nil {
				d.mu.Lock()
				d.bloatPrunedOnce = true
				d.mu.Unlock()
				if len(res.Packages) > 0 {
					d.log.Printf("pruned %d %s bloat packages in user %d", len(res.Packages), oem.Current().Name, pol.UserID)
				}
			}
		}
		if ctxBg.Err() != nil || d.isPaused() {
			return
		}
		if doSync {
			_, _ = d.syncPolicies(ctxBg, pol)
		}
	}(mctx, mcancel, policy, restoreRemaining, needPrune, needSync)
}

func (d *Daemon) startTProxySandbox(ctx context.Context, policy contracts.Policy) error {
	return d.startTProxySandboxWithPriority(ctx, policy, "")
}

func (d *Daemon) startTProxySandboxWithPriority(ctx context.Context, policy contracts.Policy, priorityPkg string) error {
	_, _, _, err := d.startTProxySandboxWithPriorityTraced(ctx, policy, priorityPkg)
	return err
}

func (d *Daemon) startTProxySandboxWithPriorityTraced(ctx context.Context, policy contracts.Policy, priorityPkg string) (thawUs, restoreUs, reconcileUs int64, err error) {
	timeout := d.userWakeTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	var priorityPkgs []string
	if priorityPkg != "" {
		priorityPkgs = []string{priorityPkg}
	}
	perf := d.getPerfConfig()
	lifeOpts := android.LifecycleOptions{
		CallerPackage:       policy.EffectiveCallerPackage(),
		PackagesListPath:    d.packagesListPath,
		CgroupRoot:          d.cgroupRoot,
		SkipAppOpsForFrozen: perf.SkipAppOpsForFrozen,
		SyncTargetOnly:      perf.SyncTargetOnly,
	}

	d.cancelMaintenance()
	d.mu.Lock()
	d.hotEscalating = false
	d.mu.Unlock()
	d.lifecycleMu.Lock()
	if d.isPaused() {
		d.lifecycleMu.Unlock()
		return 0, 0, 0, errors.New("sandbox is paused")
	}

	d.mu.Lock()
	unlockedCached := d.userUnlockedBoot
	d.mu.Unlock()
	if !unlockedCached {
		if uerr := android.StartSandboxUserAndWait(ctx, d.runner, policy.UserID, timeout); uerr != nil {
			if strings.Contains(uerr.Error(), "RUNNING_LOCKED") {
				d.lifecycleMu.Unlock()
				return thawUs, restoreUs, reconcileUs, uerr
			}
			d.log.Printf("start sandbox user %d: %v", policy.UserID, uerr)
		} else {
			d.mu.Lock()
			d.userUnlockedBoot = true
			d.mu.Unlock()
		}
	}

	alreadyReady := d.tproxyReady(policy)
	var recWg sync.WaitGroup
	var recErr error
	if alreadyReady {
		recWg.Add(1)
		go func() {
			defer recWg.Done()
			tRec := time.Now()
			recErr = d.requestReconcile(ctx, reconcileReq{clearAckBlock: true, invalidateID: true})
			reconcileUs = time.Since(tRec).Microseconds()
		}()
	}

	tThaw := time.Now()
	_, remaining, _ := android.RestoreHibernatedPriorityEx(ctx, d.runner, policy.UserID, d.resolvedHibernatedPath(), priorityPkgs, lifeOpts)
	thawUs = time.Since(tThaw).Microseconds()
	restoreUs = thawUs

	tproxyUp := alreadyReady
	if !alreadyReady {
		tproxyUp = d.ensureProxyTProxy(ctx, policy)
	}
	d.lifecycleMu.Unlock()

	if alreadyReady {
		recWg.Wait()
		if recErr != nil {
			return thawUs, restoreUs, reconcileUs, recErr
		}
	} else {
		if !tproxyUp {
			_ = d.requestReconcile(ctx, reconcileReq{clearAckBlock: true, invalidateID: true})
			return thawUs, restoreUs, reconcileUs, errors.New("proxy core not running and auto-start failed")
		}
		tRec := time.Now()
		if err := d.requestReconcile(ctx, reconcileReq{clearAckBlock: true, invalidateID: true}); err != nil {
			reconcileUs = time.Since(tRec).Microseconds()
			return thawUs, restoreUs, reconcileUs, err
		}
		reconcileUs = time.Since(tRec).Microseconds()
	}

	// Guard against stale userUnlockedBoot or partial identity failures leaving gates closed,
	// while honoring StateAckWait (up to AckWaitTimeoutNs + buffer) when external proxy capture is active.
	waitAck := func() (State, string) {
		d.mu.Lock()
		curSt, curErr, curGen, bootID := d.state, d.lastError, d.lastGen, d.bootID
		d.mu.Unlock()
		if curSt != StateAckWait {
			return curSt, curErr
		}
		deadline := time.Now().Add(3500 * time.Millisecond)
		for curSt == StateAckWait && time.Now().Before(deadline) {
			if ack := d.readCurrentAck(policy); ack != nil && ack.BootID == bootID &&
				ack.AppliedGeneration > 0 && (curGen == 0 || ack.AppliedGeneration >= curGen) {
				_ = d.requestReconcile(ctx, reconcileReq{clearAckBlock: true})
				d.mu.Lock()
				curSt, curErr, curGen = d.state, d.lastError, d.lastGen
				d.mu.Unlock()
				if curSt != StateAckWait {
					break
				}
			}
			select {
			case <-ctx.Done():
				return curSt, curErr
			case <-time.After(50 * time.Millisecond):
			}
			d.mu.Lock()
			curSt, curErr, curGen = d.state, d.lastError, d.lastGen
			d.mu.Unlock()
		}
		return curSt, curErr
	}

	stAfterRec, lastErr := waitAck()
	if stAfterRec != StateOpen {
		if stAfterRec == StateBlockedLocked {
			d.mu.Lock()
			d.userUnlockedBoot = false
			d.mu.Unlock()
			d.lifecycleMu.Lock()
			if uerr := android.StartSandboxUserAndWait(ctx, d.runner, policy.UserID, timeout); uerr == nil {
				d.mu.Lock()
				d.userUnlockedBoot = true
				d.mu.Unlock()
			}
			d.lifecycleMu.Unlock()
			if err := d.requestReconcile(ctx, reconcileReq{clearAckBlock: true, invalidateID: true}); err != nil {
				return thawUs, restoreUs, reconcileUs, err
			}
			stAfterRec, lastErr = waitAck()
		}
		if stAfterRec != StateOpen {
			return thawUs, restoreUs, reconcileUs, fmt.Errorf("sandbox gate did not open (%s: %s)", stAfterRec, lastErr)
		}
	}

	if !d.tproxyReady(policy) {
		return thawUs, restoreUs, reconcileUs, errors.New("sandbox TProxy port not ready")
	}

	d.scheduleMaintenance(policy, len(remaining) > 0)
	return thawUs, restoreUs, reconcileUs, nil
}

func (d *Daemon) resolveEffectivePauseMode(cfgMode, override string) string {
	mode := cfgMode
	if override != "" {
		mode = override
	}
	if mode == PauseModeHybrid {
		if psi, ok := android.ReadMemoryPSIAvg10(""); ok && psi >= 15.0 {
			return PauseModeDeep
		}
		if d.cgroupRoot != "" || runtime.GOOS == "linux" {
			uid := 10
			d.mu.Lock()
			if d.policy.UserID > 0 {
				uid = d.policy.UserID
			}
			d.mu.Unlock()
			if !android.HasAnyCgroupFreezeSupport(d.cgroupRoot, uid) {
				return PauseModeDeep
			}
		}
		return PauseModeHot
	}
	return mode
}

func (d *Daemon) dispatchAsyncPauseMaintenance(ctx context.Context, policy contracts.Policy, modeOverride string) {
	d.mu.Lock()
	if d.shuttingDown {
		d.mu.Unlock()
		return
	}
	baseCtx := d.superviseCtx
	if baseCtx == nil {
		baseCtx = ctx
	}
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	pctx, cancel := context.WithTimeout(baseCtx, 25*time.Second)
	d.maintWg.Add(1)
	d.mu.Unlock()
	go func() {
		defer d.maintWg.Done()
		defer cancel()
		d.pauseSandboxLifecycleLocked(pctx, policy, modeOverride)
	}()
}

func (d *Daemon) pauseSandboxLifecycleLocked(ctx context.Context, policy contracts.Policy, modeOverride string) {
	perf := d.getPerfConfig()
	callerPkg := policy.EffectiveCallerPackage()
	inbound := d.resolvedInboundName(perf, policy)
	if policy.IsTProxy() {
		defer func() {
			d.mu.Lock()
			d.hotEscalating = false
			d.mu.Unlock()
			d.notifyTimerRefresh()
		}()
		d.cancelMaintenance()
		d.lifecycleMu.Lock()
		defer d.lifecycleMu.Unlock()
		if !d.isPaused() {
			return
		}
		if n, err := FlushSandboxConnections(ctx, d.resolvedMainConfigPath(policy), inbound); err == nil && n > 0 {
			d.log.Printf("flushed %d %s connections on pause", n, inbound)
		}
		mode := d.resolveEffectivePauseMode(perf.PauseMode, modeOverride)
		pkgList := contracts.PackagesListPath
		if d.packagesListPath != "" {
			pkgList = d.packagesListPath
		}
		switch mode {
		case PauseModeHot:
			if frozen, err := android.HotFreezeSandboxUserWithOpts(ctx, d.runner, policy.UserID, d.resolvedHibernatedPath(), pkgList, d.cgroupRoot, callerPkg); err != nil {
				lifeOpts := android.LifecycleOptions{
					CallerPackage:       callerPkg,
					PackagesListPath:    pkgList,
					CgroupRoot:          d.cgroupRoot,
					SkipAppOpsForFrozen: perf.SkipAppOpsForFrozen,
				}
				if hibernated, herr := android.HibernateSandboxUserEx(ctx, d.runner, policy.UserID, d.resolvedHibernatedPath(), lifeOpts); herr != nil {
					d.log.Printf("hot freeze (%v) and deep hibernate fallback failed on user %d: %v", err, policy.UserID, herr)
				} else {
					d.log.Printf("hot freeze unavailable (%v); fell back to deep hibernation on user %d (%d user apps hibernated)", err, policy.UserID, hibernated)
				}
			} else {
				d.log.Printf("hot froze sandbox user %d (%d UIDs frozen + MADV_PAGEOUT, zero kill)", policy.UserID, frozen)
			}
		case PauseModeDeep:
			lifeOpts := android.LifecycleOptions{
				CallerPackage:       callerPkg,
				PackagesListPath:    pkgList,
				CgroupRoot:          d.cgroupRoot,
				SkipAppOpsForFrozen: perf.SkipAppOpsForFrozen,
			}
			if hibernated, err := android.HibernateSandboxUserEx(ctx, d.runner, policy.UserID, d.resolvedHibernatedPath(), lifeOpts); err != nil {
				d.log.Printf("deep hibernate sandbox user %d on pause: %v", policy.UserID, err)
			} else {
				d.log.Printf("deep hibernated sandbox user %d on pause (%d user apps hibernated, FBE unlocked)", policy.UserID, hibernated)
			}
		default:
			if stopped, err := android.StopSandboxApps(ctx, d.runner, policy.UserID, callerPkg); err != nil {
				d.log.Printf("stop sandbox apps on pause: %v", err)
			} else {
				d.log.Printf("stopped %d sandbox background apps on pause (user=%d)", stopped, policy.UserID)
			}
		}
		return
	}
	if n, err := FlushSandboxConnections(ctx, d.resolvedMainConfigPath(policy), inbound); err == nil && n > 0 {
		d.log.Printf("flushed %d %s connections on pause", n, inbound)
	}
	svcComp := policy.EffectiveServiceComponent()
	uid, _ := android.WorkClientUID(ctx, d.runner, policy.UserID, callerPkg)
	if _, running, _ := android.FindWorkServicePID(uid, callerPkg); running {
		_, _ = d.runner.Run(ctx, 4*time.Second, "", "am", "start-foreground-service",
			"--user", strconv.Itoa(policy.UserID),
			"-a", callerPkg+".action.PAUSE_VPN",
			"-n", svcComp)
		_, _ = d.runner.Run(ctx, 4*time.Second, "", "am", "stopservice",
			"--user", strconv.Itoa(policy.UserID),
			svcComp)
	}
}

func (d *Daemon) pauseSandboxWork(ctx context.Context, loaded bool, policy contracts.Policy) {
	d.pauseSandboxWorkWithMode(ctx, loaded, policy, false)
}

func (d *Daemon) pauseSandboxWorkWithMode(ctx context.Context, loaded bool, policy contracts.Policy, directReconcile bool) {
	d.pauseSandboxWorkWithExplicitMode(ctx, loaded, policy, directReconcile, "")
}

func (d *Daemon) pauseSandboxWorkWithExplicitMode(ctx context.Context, loaded bool, policy contracts.Policy, directReconcile bool, modeOverride string) {
	// Close kernel gates first (fail-closed) before tearing down sockets or stopping user processes.
	req := reconcileReq{clearAckBlock: true}
	if directReconcile {
		_ = d.reconcileOnce(ctx, req)
	} else {
		_ = d.requestReconcile(ctx, req)
	}
	if !loaded {
		return
	}
	d.pauseSandboxLifecycleLocked(ctx, policy, modeOverride)
}

// HandleRPC serves the whitelisted RPCs forwarded by sandbox_broker on guard.sock.
func (d *Daemon) HandleRPC(ctx context.Context, req contracts.RPCRequest) contracts.RPCResponse {
	switch req.Op {
	case contracts.OpGetStatus:
		return contracts.RPCResponse{ID: req.ID, OK: true, Error: "", Data: d.buildStatusData(ctx)}

	case contracts.OpImportExisting:
		d.mu.Lock()
		loaded, policy := d.policyLoaded, d.policy
		d.mu.Unlock()
		if !loaded {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: "policy not pinned", Data: map[string]any{}}
		}
		u := strconv.Itoa(policy.UserID)
		out, err := d.runner.Run(ctx, 15*time.Second, "", "cmd", "package", "install-existing", "--user", u, req.Pkg)
		if err != nil {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: map[string]any{"output": strings.TrimSpace(out)}}
		}
		d.evictCachedLauncher(req.Pkg)
		hideRes, hideErr := android.SyncHideApps(ctx, d.runner, policy.UserID, policy.Serial)
		polRes, _ := d.syncPolicies(ctx, policy)
		data := map[string]any{
			"pkg":           req.Pkg,
			"user_id":       policy.UserID,
			"installed":     true,
			"output":        strings.TrimSpace(out),
			"hide_synced":   hideErr == nil,
			"hide_result":   hideRes,
			"policy_result": polRes,
		}
		if hideErr != nil {
			data["hide_warning"] = hideErr.Error()
		}
		return contracts.RPCResponse{ID: req.ID, OK: true, Error: "", Data: data}

	case contracts.OpInstallApk:
		d.mu.Lock()
		loaded, policy := d.policyLoaded, d.policy
		d.mu.Unlock()
		if !loaded {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: "policy not pinned", Data: map[string]any{}}
		}
		res, err := android.InstallSandboxAPKs(ctx, d.runner, policy.UserID, req.ApkPaths, d.apkStagingDirs)
		if err != nil {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: map[string]any{}}
		}
		d.invalidateLaunchCaches()
		hideRes, hideErr := android.SyncHideApps(ctx, d.runner, policy.UserID, policy.Serial)
		polRes, _ := d.syncPolicies(ctx, policy)
		return contracts.RPCResponse{ID: req.ID, OK: true, Error: "", Data: map[string]any{
			"install":       res,
			"hide_synced":   hideErr == nil,
			"hide_result":   hideRes,
			"policy_result": polRes,
		}}

	case contracts.OpStartVPN:
		loaded, policy, err := d.setDesiredPaused(false, true, false)
		if err != nil {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: map[string]any{}}
		}
		if !loaded {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: "policy not pinned", Data: map[string]any{}}
		}
		if policy.IsTProxy() {
			if err := d.startTProxySandbox(ctx, policy); err != nil {
				return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: d.buildStatusData(ctx)}
			}
			return contracts.RPCResponse{ID: req.ID, OK: true, Error: "", Data: d.buildStatusData(ctx)}
		}
		callerPkg := policy.EffectiveCallerPackage()
		_ = android.EnsureWorkPermissions(ctx, d.runner, policy.UserID, callerPkg)
		if uid, err := android.WorkClientUID(ctx, d.runner, policy.UserID, callerPkg); err == nil {
			if pid, running, _ := android.FindWorkServicePID(uid, callerPkg); running {
				fs := inspectAnyFreeze(uid, pid)
				if fs.Frozen {
					_ = unfreezeAny(uid, pid, fs)
				}
			}
		}
		if _, err := d.runner.Run(ctx, 5*time.Second, "", "am", "start-foreground-service",
			"--user", strconv.Itoa(policy.UserID),
			"-a", callerPkg+".action.START_VPN",
			"-n", policy.EffectiveServiceComponent()); err != nil {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: map[string]any{}}
		}
		_ = d.requestReconcile(ctx, reconcileReq{clearAckBlock: true, invalidateID: true})
		return contracts.RPCResponse{ID: req.ID, OK: true, Error: "", Data: d.buildStatusData(ctx)}

	case contracts.OpPauseVPN:
		loaded, policy, err := d.setDesiredPaused(true, false, false)
		if err != nil {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: map[string]any{}}
		}
		d.pauseSandboxWork(ctx, loaded, policy)
		return contracts.RPCResponse{ID: req.ID, OK: true, Error: "", Data: d.buildStatusData(ctx)}

	case contracts.OpReloadConfig:
		d.mu.Lock()
		loaded, policy, gen, pgen := d.policyLoaded, d.policy, d.lastGen, d.lastPendingGen
		d.mu.Unlock()
		if !loaded {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: "policy not pinned", Data: map[string]any{}}
		}
		callerPkg := policy.EffectiveCallerPackage()
		uid, err := android.WorkClientUID(ctx, d.runner, policy.UserID, callerPkg)
		if err != nil {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: map[string]any{}}
		}
		quicMode := "reject"
		logLevel := "warning"
		if req.Config != nil {
			if req.Config.QuicUDP443Mode != "" {
				quicMode = req.Config.QuicUDP443Mode
			}
			if req.Config.LogLevel != "" {
				logLevel = req.Config.LogLevel
			}
		}
		cfgDir := d.workCfgDir
		if cfgDir == "" {
			cfgDir = contracts.WorkCfgDir
		}
		cfgPath := filepath.Join(cfgDir, fmt.Sprintf("u%d.pending.json", policy.UserID))
		if existing, err := readPendingConfig(cfgPath); err == nil && existing.Generation > pgen {
			pgen = existing.Generation
		}
		if gen > pgen {
			pgen = gen
		}
		nextPendingGen := pgen + 1
		pending := contracts.PendingConfig{
			Version:        1,
			Generation:     nextPendingGen,
			TSMonoNs:       sysio.MonotonicNowNs(),
			MTU:            contracts.SandboxMTU,
			QuicUDP443Mode: quicMode,
			Overrides:      map[string]string{"log_level": logLevel},
		}
		b, err := json.Marshal(pending)
		if err != nil {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: map[string]any{}}
		}
		if err := sysio.WriteAtomic(cfgPath, append(b, '\n'), sysio.WriteAtomicOptions{
			Perm:    0640,
			UID:     0,
			GID:     uid,
			SELinux: contracts.SELinuxCfgFile,
		}); err != nil {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: map[string]any{}}
		}
		d.mu.Lock()
		d.lastPendingGen = nextPendingGen
		paused := d.paused
		d.mu.Unlock()
		if !paused {
			if policy.IsTProxy() {
				_ = d.requestReconcile(ctx, reconcileReq{})
			} else {
				callerPkg := policy.EffectiveCallerPackage()
				_, _ = d.runner.Run(ctx, 4*time.Second, "", "am", "start-foreground-service",
					"--user", strconv.Itoa(policy.UserID),
					"-a", callerPkg+".action.RELOAD_CONFIG",
					"-n", policy.EffectiveServiceComponent())
			}
		}
		return contracts.RPCResponse{ID: req.ID, OK: true, Error: "", Data: map[string]any{
			"config_path":      cfgPath,
			"generation":       pending.Generation,
			"mtu":              pending.MTU,
			"quic_udp443_mode": pending.QuicUDP443Mode,
		}}

	case contracts.OpSyncHideApps:
		d.mu.Lock()
		loaded, policy := d.policyLoaded, d.policy
		d.mu.Unlock()
		if !loaded {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: "policy not pinned", Data: map[string]any{}}
		}
		res, err := android.SyncHideApps(ctx, d.runner, policy.UserID, policy.Serial)
		if err != nil {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: map[string]any{}}
		}
		return contracts.RPCResponse{ID: req.ID, OK: true, Error: "", Data: res}

	case contracts.OpRunProbe:
		data, err := d.runOnDemandProbe(ctx)
		if err != nil {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: data}
		}
		return contracts.RPCResponse{ID: req.ID, OK: true, Error: "", Data: data}

	case contracts.OpLaunchApp:
		tTotal := time.Now()
		d.mu.Lock()
		d.wakeSeq++
		loaded, policy := d.policyLoaded, d.policy
		wasPaused := d.paused
		curState := d.state
		d.mu.Unlock()
		if !loaded {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: "policy not pinned", Data: map[string]any{}}
		}
		perf := d.getPerfConfig()
		var thawUs, restoreUs, reconcileUs int64
		fastPath := false

		if wasPaused || curState != StateOpen {
			if _, _, err := d.setDesiredPaused(false, true, false); err != nil {
				return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: map[string]any{}}
			}
			if policy.IsTProxy() {
				var err error
				thawUs, restoreUs, reconcileUs, err = d.startTProxySandboxWithPriorityTraced(ctx, policy, req.Pkg)
				if err != nil {
					return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: d.buildStatusData(ctx)}
				}
			} else {
				tRec := time.Now()
				_ = d.requestReconcile(ctx, reconcileReq{clearAckBlock: true, invalidateID: true})
				reconcileUs = time.Since(tRec).Microseconds()
			}
		} else if policy.IsTProxy() {
			fastPath = true
			hibPath := d.resolvedHibernatedPath()
			if st := android.ReadHibernatedState(hibPath); len(st.Packages) > 0 || len(st.FrozenUIDs) > 0 {
				d.cancelMaintenance()
				d.lifecycleMu.Lock()
				var remaining []string
				if !d.isPaused() {
					tThaw := time.Now()
					lifeOpts := android.LifecycleOptions{
						CallerPackage:       policy.EffectiveCallerPackage(),
						PackagesListPath:    d.packagesListPath,
						CgroupRoot:          d.cgroupRoot,
						SkipAppOpsForFrozen: perf.SkipAppOpsForFrozen,
						SyncTargetOnly:      perf.SyncTargetOnly,
					}
					_, remaining, _ = android.RestoreHibernatedPriorityEx(ctx, d.runner, policy.UserID, hibPath, []string{req.Pkg}, lifeOpts)
					thawUs = time.Since(tThaw).Microseconds()
					restoreUs = thawUs
				}
				d.lifecycleMu.Unlock()
				if len(remaining) > 0 && !d.isPaused() {
					d.scheduleMaintenance(policy, true)
				}
			}
		} else {
			fastPath = true
		}

		pkgList := contracts.PackagesListPath
		if d.packagesListPath != "" {
			pkgList = d.packagesListPath
		}
		if perf.LaunchBoostMs > 0 && req.Pkg != "" {
			if targetUID := ResolvePackageUIDForUser(pkgList, policy.UserID, req.Pkg); targetUID > 0 {
				_ = android.BoostUIDLaunch(d.cgroupRoot, targetUID, time.Duration(perf.LaunchBoostMs)*time.Millisecond)
			}
		}
		if !fastPath && req.Pkg != "" {
			go android.PrewarmSandboxAppFiles(pkgList, req.Pkg)
		}

		tLaunch := time.Now()
		var launchErr error
		if req.Activity != "" {
			launchErr = android.LaunchSandboxAppAsRoot(ctx, d.runner, policy.UserID, req.Pkg, req.Activity)
		} else if cachedComp := d.cachedLauncher(req.Pkg); cachedComp != "" {
			launchErr = android.LaunchComponentAsRoot(ctx, d.runner, policy.UserID, cachedComp)
			if launchErr != nil {
				d.evictCachedLauncher(req.Pkg)
				d.mu.Lock()
				d.userUnlockedBoot = false
				d.mu.Unlock()
				timeout := d.userWakeTimeout
				if timeout <= 0 {
					timeout = 5 * time.Second
				}
				if uerr := android.StartSandboxUserAndWait(ctx, d.runner, policy.UserID, timeout); uerr == nil {
					d.mu.Lock()
					d.userUnlockedBoot = true
					d.mu.Unlock()
				}
				if resolved, rerr := android.ResolveLauncherComponent(ctx, d.runner, policy.UserID, req.Pkg); rerr == nil {
					if launchErr = android.LaunchComponentAsRoot(ctx, d.runner, policy.UserID, resolved); launchErr == nil {
						d.setCachedLauncher(req.Pkg, resolved)
					}
				} else {
					launchErr = rerr
				}
			}
		} else {
			if resolved, rerr := android.ResolveLauncherComponent(ctx, d.runner, policy.UserID, req.Pkg); rerr == nil {
				if launchErr = android.LaunchComponentAsRoot(ctx, d.runner, policy.UserID, resolved); launchErr == nil {
					d.setCachedLauncher(req.Pkg, resolved)
				}
			} else {
				launchErr = rerr
			}
		}
		launchUs := time.Since(tLaunch).Microseconds()
		if launchErr != nil {
			d.mu.Lock()
			d.userUnlockedBoot = false
			d.mu.Unlock()
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: launchErr.Error(), Data: d.buildStatusData(ctx)}
		}
		d.recordLaunchTrace(LaunchTrace{
			Op:          contracts.OpLaunchApp,
			Pkg:         req.Pkg,
			ThawUs:      thawUs,
			RestoreUs:   restoreUs,
			ReconcileUs: reconcileUs,
			LaunchUs:    launchUs,
			TotalUs:     time.Since(tTotal).Microseconds(),
			FastPath:    fastPath,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
		})
		return contracts.RPCResponse{ID: req.ID, OK: true, Error: "", Data: d.buildStatusData(ctx)}

	case contracts.OpStopApp:
		d.mu.Lock()
		loaded, policy := d.policyLoaded, d.policy
		d.mu.Unlock()
		if !loaded {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: "policy not pinned", Data: map[string]any{}}
		}
		if err := android.StopSandboxApp(ctx, d.runner, policy.UserID, req.Pkg, policy.EffectiveCallerPackage()); err != nil {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: d.buildStatusData(ctx)}
		}
		return contracts.RPCResponse{ID: req.ID, OK: true, Error: "", Data: d.buildStatusData(ctx)}

	case contracts.OpRemoveApp:
		d.mu.Lock()
		loaded, policy := d.policyLoaded, d.policy
		d.mu.Unlock()
		if !loaded {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: "policy not pinned", Data: map[string]any{}}
		}
		if _, err := android.RemoveSandboxApp(ctx, d.runner, policy.UserID, req.Pkg, policy.EffectiveCallerPackage()); err != nil {
			return contracts.RPCResponse{ID: req.ID, OK: false, Error: err.Error(), Data: d.buildStatusData(ctx)}
		}
		d.evictCachedLauncher(req.Pkg)
		_, _ = android.SyncHideApps(ctx, d.runner, policy.UserID, policy.Serial)
		return contracts.RPCResponse{ID: req.ID, OK: true, Error: "", Data: d.buildStatusData(ctx)}

	default:
		return contracts.RPCResponse{ID: req.ID, OK: false, Error: "unsupported op", Data: map[string]any{}}
	}
}

func (d *Daemon) HandleCtl(ctx context.Context, cmd string, args []string) (string, error) {
	switch cmd {
	case "upgrade-begin":
		ttl := contracts.DefaultUpgradeTTLSeconds
		if len(args) > 0 {
			v, err := strconv.Atoi(args[0])
			if err != nil || v <= 0 || v > contracts.MaxUpgradeTTLSeconds {
				return "", fmt.Errorf("invalid ttl %q", args[0])
			}
			ttl = v
		}
		fence := contracts.UpgradeFence{
			BootID:      d.bootID,
			Active:      true,
			UntilMonoNs: sysio.MonotonicNowNs() + int64(ttl)*int64(time.Second),
			TTLSeconds:  ttl,
		}
		fencePath := d.upgradeFencePath
		if fencePath == "" {
			fencePath = contracts.UpgradeFencePath
		}
		ackPath := d.sandboxAckPath
		if ackPath == "" {
			ackPath = contracts.SandboxAckPath
		}
		b, _ := json.Marshal(fence)
		_ = sysio.WriteAtomic(fencePath, append(b, '\n'), sysio.WriteAtomicOptions{Perm: 0600, UID: 0, GID: 0})
		_ = removeIfExist(ackPath)
		d.mu.Lock()
		d.fence = fence
		d.mu.Unlock()
		if err := d.requestReconcile(ctx, reconcileReq{}); err != nil {
			return "", err
		}
		return fmt.Sprintf("upgrading fence active ttl=%ds", ttl), nil

	case "upgrade-end":
		fencePath := d.upgradeFencePath
		if fencePath == "" {
			fencePath = contracts.UpgradeFencePath
		}
		_ = removeIfExist(fencePath)
		d.mu.Lock()
		d.fence = contracts.UpgradeFence{}
		d.mu.Unlock()
		if err := d.requestReconcile(ctx, reconcileReq{clearAckBlock: true}); err != nil {
			return "", err
		}
		return "upgrading fence cleared", nil

	case "reload-policy":
		if p, err := ReadPolicy(); err == nil {
			d.mu.Lock()
			d.policy = p
			d.policyLoaded = true
			d.cachedID = nil
			d.mu.Unlock()
		}
		_ = d.requestReconcile(ctx, reconcileReq{clearAckBlock: true, invalidateID: true, refreshCert: true, syncHide: true})
		return "reloaded", nil

	case "status":
		b, err := json.MarshalIndent(d.buildStatusData(ctx), "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil

	case "sync-hide":
		d.mu.Lock()
		loaded, policy := d.policyLoaded, d.policy
		d.mu.Unlock()
		if !loaded {
			return "", errors.New("policy not pinned")
		}
		res, err := android.SyncHideApps(ctx, d.runner, policy.UserID, policy.Serial)
		if err != nil {
			return "", err
		}
		b, _ := json.Marshal(res)
		return string(b), nil

	case "sync-policies":
		d.mu.Lock()
		loaded, policy := d.policyLoaded, d.policy
		d.mu.Unlock()
		if !loaded {
			return "", errors.New("policy not pinned")
		}
		res, err := d.syncPolicies(ctx, policy)
		if err != nil {
			return "", err
		}
		b, _ := json.Marshal(res)
		return string(b), nil

	case "perf-status":
		perf := d.getPerfConfig()
		b, err := json.MarshalIndent(perf, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil

	case "perf-trace":
		b, err := json.MarshalIndent(d.getLaunchTraces(), "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil

	case "prune-bloat":
		d.mu.Lock()
		loaded, policy := d.policyLoaded, d.policy
		d.mu.Unlock()
		if !loaded {
			return "", errors.New("policy not pinned")
		}
		res, err := android.PruneSandboxBloat(ctx, d.runner, policy.UserID, d.resolvedPrunedPath(), policy.EffectiveCallerPackage())
		if err != nil {
			return "", err
		}
		d.mu.Lock()
		d.bloatPrunedOnce = true
		d.mu.Unlock()
		b, _ := json.MarshalIndent(res, "", "  ")
		return string(b), nil

	case "restore-bloat":
		d.mu.Lock()
		loaded, policy := d.policyLoaded, d.policy
		d.mu.Unlock()
		if !loaded {
			return "", errors.New("policy not pinned")
		}
		res, err := android.RestoreSandboxBloat(ctx, d.runner, policy.UserID, d.resolvedPrunedPath())
		if err != nil {
			return "", err
		}
		d.mu.Lock()
		d.bloatPrunedOnce = false
		d.mu.Unlock()
		b, _ := json.MarshalIndent(res, "", "  ")
		return string(b), nil

	case "flush-sandbox-conns":
		perf := d.getPerfConfig()
		d.mu.Lock()
		pol := d.policy
		d.mu.Unlock()
		inbound := d.resolvedInboundName(perf, pol)
		n, err := FlushSandboxConnections(ctx, d.resolvedMainConfigPath(pol), inbound)
		if err != nil {
			return "", err
		}
		b, _ := json.Marshal(map[string]any{"inbound": inbound, "closed": n})
		return string(b), nil

	case "set-app-locale":
		if len(args) != 2 {
			return "", errors.New("usage: set-app-locale <package> <locale|clear>")
		}
		d.mu.Lock()
		loaded, policy := d.policyLoaded, d.policy
		d.mu.Unlock()
		if !loaded {
			return "", errors.New("policy not pinned")
		}
		pkg, loc := args[0], args[1]
		if err := android.SetSandboxAppLocale(ctx, d.runner, policy.UserID, pkg, loc, policy.EffectiveCallerPackage()); err != nil {
			return "", err
		}
		perf := LoadPerfConfig(d.resolvedPerfPath())
		if perf.LocaleOverrides == nil {
			perf.LocaleOverrides = map[string]string{}
		}
		if strings.EqualFold(loc, "clear") || strings.EqualFold(loc, "none") {
			perf.LocaleOverrides[pkg] = ""
		} else {
			perf.LocaleOverrides[pkg] = loc
		}
		_ = WritePerfConfig(d.resolvedPerfPath(), perf)
		d.setPerfConfig(perf)
		b, _ := json.Marshal(map[string]any{"user_id": policy.UserID, "package": pkg, "locale": perf.LocaleOverrides[pkg]})
		return string(b), nil

	case "install-apk":
		if len(args) == 0 {
			return "", errors.New("install-apk requires at least 1 apk path")
		}
		for _, p := range args {
			if len(d.apkStagingDirs) == 0 && !rpc.IsSafeAPKPath(p) {
				return "", fmt.Errorf("unsafe apk path %q", p)
			}
		}
		d.mu.Lock()
		loaded, policy := d.policyLoaded, d.policy
		d.mu.Unlock()
		if !loaded {
			return "", errors.New("policy not pinned")
		}
		res, err := android.InstallSandboxAPKs(ctx, d.runner, policy.UserID, args, d.apkStagingDirs)
		if err != nil {
			return "", err
		}
		d.invalidateLaunchCaches()
		_, _ = android.SyncHideApps(ctx, d.runner, policy.UserID, policy.Serial)
		_, _ = d.syncPolicies(ctx, policy)
		b, _ := json.Marshal(res)
		return string(b), nil

	case "stealth-status":
		b, err := json.MarshalIndent(d.ReadStealthStatus(), "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil

	case "variant-info":
		b, err := json.MarshalIndent(buildinfo.Current(), "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil

	case "preset-apply":
		if len(args) != 1 {
			return "", errors.New("usage: preset-apply <preset.json>")
		}
		cfg, err := d.ApplyPresetFile(ctx, args[0])
		if err != nil {
			return "", err
		}
		b, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b), nil

	case "stealth-toggle":
		if len(args) != 1 || (args[0] != "on" && args[0] != "off") {
			return "", errors.New("usage: stealth-toggle on|off")
		}
		cfg, err := d.ToggleStealth(args[0] == "on")
		if err != nil {
			return "", err
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		return string(b), nil

	case "block", "pause-sandbox", "pause-hot":
		loaded, policy, _ := d.setDesiredPaused(true, false, true)
		if cmd == "pause-hot" {
			d.pauseSandboxWorkWithExplicitMode(ctx, loaded, policy, false, PauseModeHot)
			return "hot-paused", nil
		}
		if cmd == "pause-sandbox" {
			d.pauseSandboxWork(ctx, loaded, policy)
			return "paused", nil
		}
		if err := d.requestReconcile(ctx, reconcileReq{clearAckBlock: true}); err != nil {
			return "", err
		}
		return "blocked", nil

	case "start-sandbox":
		loaded, policy, err := d.setDesiredPaused(false, true, false)
		if err != nil {
			return "", err
		}
		if !loaded {
			return "", errors.New("policy not pinned")
		}
		if policy.IsTProxy() {
			if err := d.startTProxySandbox(ctx, policy); err != nil {
				return "", err
			}
			return "started", nil
		}
		if err := d.requestReconcile(ctx, reconcileReq{clearAckBlock: true, invalidateID: true}); err != nil {
			return "", err
		}
		return "started", nil

	default:
		return "", fmt.Errorf("unknown ctl command %q", cmd)
	}
}

func (d *Daemon) buildStatusData(ctx context.Context) map[string]any {
	d.mu.Lock()
	state := d.state
	paused := d.paused
	loaded := d.policyLoaded
	policy := d.policy
	fence := d.fence
	curEx := d.currentExemption
	sess := d.lastSession
	rawArmed := d.lastRawArmed
	openGate := d.lastOpen
	lastErr := d.lastError
	d.mu.Unlock()

	var vpnStatus *contracts.VPNStatus
	var frozen bool
	var freezeEvidence string
	stuckWork, crossPool := 0, 0

	if loaded {
		callerPkg := policy.EffectiveCallerPackage()
		uidStart, uidEnd := policy.UIDRange()
		stuckWork, crossPool = CountStuckWorkSockets(uidStart, uidEnd)
		if !policy.IsTProxy() {
			if cid, err := android.WorkClientUID(ctx, d.runner, policy.UserID, callerPkg); err == nil {
				vpnStatus, _ = d.readWorkVPNStatus(policy.UserID, cid, callerPkg)
				if pid, alive, _ := android.FindWorkServicePID(cid, callerPkg); alive {
					fs := inspectAnyFreeze(cid, pid)
					frozen = fs.Frozen
					freezeEvidence = fs.Evidence
				}
			}
		}
	}
	privDNS, _ := d.runner.Run(ctx, 2*time.Second, "", "settings", "get", "global", "private_dns_mode")
	privDNS = strings.TrimSpace(privDNS)

	_, _, disabledFlag := d.resolvedStealthPaths()
	_, flagErr := os.Stat(disabledFlag)
	zygiskDisabled := flagErr == nil
	stealthTries := 0
	if raw, err := os.ReadFile(d.resolvedStealthBootTriesPath()); err == nil {
		if n, perr := strconv.Atoi(strings.TrimSpace(string(raw))); perr == nil && n >= 0 {
			stealthTries = n
		}
	}

	data := map[string]any{
		"version":              contracts.Version,
		"variant":              buildinfo.Current(),
		"state":                string(state),
		"paused":               paused,
		"boot_id":              d.bootID,
		"policy_loaded":        loaded,
		"user_id":              policy.UserID,
		"serial":               policy.Serial,
		"main_upgrading":       FenceActive(fence, d.bootID, sysio.MonotonicNowNs()),
		"sbw_raw_armed":        rawArmed,
		"sbw_open":             openGate,
		"frozen":               frozen,
		"freeze_evidence":      freezeEvidence,
		"zygisk_disabled":      zygiskDisabled,
		"active_preset":        d.readActivePresetName(),
		"stealth_boot_tries":   stealthTries,
		"private_dns_mode":     privDNS,
		"private_dns_warning":  privDNS == "hostname",
		"stuck_work_sockets":   stuckWork,
		"cross_pool_12c6_hits": crossPool,
		"last_error":           lastErr,
	}
	if curEx != nil {
		data["exemption"] = curEx
	}
	if ack := d.readCurrentAck(policy); ack != nil {
		data["sandbox_ack"] = ack
	}
	if sess != nil {
		data["session"] = sess
	}
	pendingCfg := d.resolvePendingConfig(loaded, policy, vpnStatus)
	perfCfg := d.getPerfConfig()
	if vpnStatus != nil {
		data["vpn_status"] = vpnStatus
	} else if loaded && policy.IsTProxy() {
		tproxyOK := d.tproxyReady(policy)
		data["mode"] = contracts.ModeTProxy
		data["tproxy_port"] = policy.TProxyPort
		data["tproxy_ready"] = tproxyOK
		quicModeStr := "allow"
		if perfCfg.KernelRejectQuicUDP443 {
			quicModeStr = "reject"
		}
		if qm, ok := pendingCfg["quic_udp443_mode"].(string); ok && qm == "allow" {
			quicModeStr = "allow"
		}
		data["vpn_status"] = map[string]any{
			"running":          openGate,
			"exit_ip":          policy.EndpointV4,
			"mtu":              1500,
			"quic_udp443_mode": quicModeStr,
		}
	}
	data["perf"] = perfCfg
	data["pending_config"] = pendingCfg
	if loaded {
		data["u10_running_procs"] = android.CountRunningUserProcessesWithRoot(d.cgroupRoot, policy.UserID)
		hib := android.ReadHibernatedState(d.resolvedHibernatedPath())
		data["hibernated_count"] = len(hib.Packages)
		data["hot_frozen"] = hib.HotFrozen
		if hib.FrozenUIDs != nil {
			data["frozen_uids"] = hib.FrozenUIDs
		} else {
			data["frozen_uids"] = []int{}
		}
		if apps, err := android.ListSandboxApps(ctx, d.runner, policy.UserID, policy.EffectiveCallerPackage(), "com.sandbox.verify"); err == nil {
			data["sandbox_apps"] = apps
		} else {
			data["sandbox_apps"] = []string{}
		}
	}
	if traces := d.getLaunchTraces(); len(traces) > 0 {
		data["last_launch_trace"] = traces[len(traces)-1]
	}
	return data
}

func (d *Daemon) tproxyReady(policy contracts.Policy) bool {
	if d.probeTProxyReady != nil {
		return d.probeTProxyReady(policy.TProxyPort)
	}
	return android.TProxyReadyProbe(policy.TProxyPort, policy.EffectiveProxyCorePIDPath(), policy.ProxyCoreProcess)
}

func readPendingConfig(path string) (contracts.PendingConfig, error) {
	raw, err := sysio.ReadRootOwnedSmallFilePerm(path, contracts.MaxSmallFileBytes, 0037)
	if err != nil {
		return contracts.PendingConfig{}, err
	}
	var cfg contracts.PendingConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return contracts.PendingConfig{}, err
	}
	return cfg, nil
}

func (d *Daemon) resolvePendingConfig(loaded bool, policy contracts.Policy, vpnStatus *contracts.VPNStatus) map[string]any {
	mtu := contracts.SandboxMTU
	quicMode := "reject"
	var gen uint64

	if vpnStatus != nil {
		if vpnStatus.MTU > 0 {
			mtu = vpnStatus.MTU
		}
		if vpnStatus.QUICUDP443Mode == "allow" || vpnStatus.QUICUDP443Mode == "reject" {
			quicMode = vpnStatus.QUICUDP443Mode
		}
		if vpnStatus.ConfigGeneration > 0 {
			gen = uint64(vpnStatus.ConfigGeneration)
		}
	}

	if loaded {
		cfgDir := d.workCfgDir
		if cfgDir == "" {
			cfgDir = contracts.WorkCfgDir
		}
		cfgPath := filepath.Join(cfgDir, fmt.Sprintf("u%d.pending.json", policy.UserID))
		if pending, err := readPendingConfig(cfgPath); err == nil {
			if pending.Generation >= gen {
				if pending.MTU > 0 {
					mtu = pending.MTU
				}
				if pending.QuicUDP443Mode == "allow" || pending.QuicUDP443Mode == "reject" {
					quicMode = pending.QuicUDP443Mode
				}
				if pending.Generation > 0 {
					gen = pending.Generation
				}
			}
		}
	}

	return map[string]any{
		"mtu":              mtu,
		"quic_udp443_mode": quicMode,
		"generation":       gen,
	}
}

func ParseInstrumentationResult(output string) (map[string]any, error) {
	hasSuccessCode := false
	var networkJSON string
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if line == "INSTRUMENTATION_CODE: -1" {
			hasSuccessCode = true
			continue
		}
		if strings.HasPrefix(line, "INSTRUMENTATION_RESULT: network=") {
			networkJSON = strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_RESULT: network="))
		} else if networkJSON == "" {
			if idx := strings.Index(line, "network={"); idx >= 0 {
				networkJSON = strings.TrimSpace(line[idx+len("network="):])
			}
		}
	}
	if !hasSuccessCode {
		return nil, errors.New("am instrument did not return INSTRUMENTATION_CODE: -1")
	}
	if networkJSON == "" {
		return nil, errors.New("am instrument missing INSTRUMENTATION_RESULT network JSON")
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(networkJSON), &parsed); err != nil {
		return nil, fmt.Errorf("am instrument invalid network JSON: %w", err)
	}
	return parsed, nil
}

func (d *Daemon) runOnDemandProbe(ctx context.Context) (map[string]any, error) {
	res := d.buildStatusData(ctx)
	d.mu.Lock()
	loaded, policy, sess := d.policyLoaded, d.policy, d.lastSession
	d.mu.Unlock()
	if !loaded {
		return res, errors.New("policy not pinned")
	}
	routeChecks := map[string]any{}
	if sess != nil {
		innerUID := policy.UserID*contracts.AndroidUserWidth + contracts.MinAppID
		if innerUID == sess.ClientUID {
			innerUID++
		}
		routeChecks["fakeip_198_19"] = android.CheckWorkRoute(ctx, d.runner, contracts.FakeIPProbe, innerUID, sess.UplinkNetID, sess.TunIf) == nil
		if policy.EndpointV4 != "" {
			outerMark := sess.UplinkNetID | contracts.ProtectedVPNBit | contracts.ExplicitNetworkBit
			routeChecks["outer_endpoint"] = android.CheckWorkRoute(ctx, d.runner, policy.EndpointV4, sess.ClientUID, outerMark, sess.UplinkIf) == nil
		}
		dnsMark := sess.VPNNetID | contracts.ExplicitNetworkBit | contracts.ProtectedVPNBit | contracts.SystemPermission
		routeChecks["portal_dns4"] = android.CheckWorkRoute(ctx, d.runner, policy.PortalDNS4, 1051, dnsMark, sess.TunIf) == nil
	}
	res["route_checks"] = routeChecks

	// If independent probe APK is installed in the sandbox user, run it on demand.
	u := strconv.Itoa(policy.UserID)
	pkgs, err := d.runner.Run(ctx, 3*time.Second, "", "cmd", "package", "list", "packages", "--user", u, contracts.VerifyProbePackage)
	if err == nil && strings.Contains(pkgs, "package:"+contracts.VerifyProbePackage) {
		res["probe_apk_installed"] = true
		out, ierr := d.runner.Run(ctx, 20*time.Second, "", "am", "instrument", "-w", "-r", "--user", u,
			contracts.VerifyProbePackage+"/.NetworkProbe")
		res["instrument_output"] = strings.TrimSpace(out)
		if ierr != nil {
			res["instrument_ok"] = false
			return res, fmt.Errorf("am instrument failed: %w", ierr)
		}
		parsed, perr := ParseInstrumentationResult(out)
		if perr != nil {
			res["instrument_ok"] = false
			return res, perr
		}
		res["instrument_ok"] = true
		res["probe_result"] = parsed
	} else {
		res["probe_apk_installed"] = false
	}
	return res, nil
}

// CountStuckWorkSockets scans /proc/net/tcp for SYN_SENT (state 02) sockets owned by [uidStart..uidEnd]
// targeting sandbox Fake-IP 198.19.x.x (little-endian ....13C6:) or cross-pool 198.18.x.x (....12C6:).
func CountStuckWorkSockets(uidStart, uidEnd int) (work13C6 int, cross12C6 int) {
	f, err := os.Open(contracts.ProcNetTCP)
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	return CountStuckSocketsFromReader(bufio.NewScanner(f), uidStart, uidEnd)
}

func CountStuckSocketsFromReader(sc *bufio.Scanner, uidStart, uidEnd int) (work13C6 int, cross12C6 int) {
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue
		}
		if fields[3] != "02" {
			continue
		}
		uid, err := strconv.Atoi(fields[7])
		if err != nil || uid < uidStart || uid > uidEnd {
			continue
		}
		addr := strings.ToUpper(fields[2])
		ipHex, _, ok := strings.Cut(addr, ":")
		if !ok {
			continue
		}
		switch {
		case strings.HasSuffix(ipHex, "13C6"):
			work13C6++
		case strings.HasSuffix(ipHex, "12C6"):
			cross12C6++
		}
	}
	return work13C6, cross12C6
}

func ensureDevDirs() {
	dirs := []struct {
		path string
		perm os.FileMode
		ctx  string
	}{
		{contracts.BrokerSockDir, 0711, contracts.SELinuxSockDir},
		{contracts.PrivDir, 0700, contracts.SELinuxPrivDir},
		{contracts.WorkCfgDir, 0711, contracts.SELinuxCfgDir},
	}
	for _, d := range dirs {
		_ = os.MkdirAll(d.path, d.perm)
		_ = os.Chmod(d.path, d.perm)
		_ = os.Chown(d.path, 0, 0)
		_ = sysio.Lsetfilecon(d.path, d.ctx)
	}
}

func removeIfExist(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// RunCtl executes `sandbox_guard ctl <subcmd> [args...]`.
func isCtlDaemonUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}

func RunCtl(args []string) error {
	if len(args) == 0 {
		return errors.New("missing ctl subcommand")
	}
	sub := args[0]
	rest := args[1:]
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	runner := netfilter.ExecRunner{}
	nf := netfilter.NewController()

	switch sub {
	case "boot":
		ensureDevDirs()
		_ = removeIfExist(contracts.SandboxAckPath)
		bootID, err := sysio.ReadBootID()
		if err != nil {
			return err
		}
		if f, err := ReadUpgradeFence(bootID); err != nil || !f.Active {
			_ = removeIfExist(contracts.UpgradeFencePath)
		}
		p, err := ReadPolicy()
		if err != nil {
			fmt.Println("unpinned")
			return nil
		}
		var gen uint64 = 1
		prevClientUID := 0
		if prev, err := ReadExemption(contracts.ExemptionPath); err == nil {
			if prev.Generation >= 1 {
				gen = prev.Generation + 1
			}
			if contracts.ValidClientUID(p.UserID, prev.ClientUID) {
				prevClientUID = prev.ClientUID
			}
		}
		ex := BuildBlockedExemption(p, bootID, prevClientUID, gen)
		if b, err := json.Marshal(ex); err == nil {
			_ = sysio.WriteAtomic(contracts.ExemptionPath, append(b, '\n'), sysio.WriteAtomicOptions{Perm: 0600, UID: 0, GID: 0})
		}
		_ = SyncPerfConfig(contracts.PerfConfigPath)
		bootD := &Daemon{}
		_, _ = bootD.SyncStealthConfig(p, prevClientUID)
		extCap, _ := nf.DetectProxyCapture(ctx, p.ProxySkipPrefix)
		spec := closedGateSpec(p, extCap)
		if err := nf.ApplyOrVerify(ctx, spec, false); err != nil {
			return err
		}
		fmt.Printf("blocked user=%d serial=%d gen=%d\n", p.UserID, p.Serial, gen)
		return nil

	case "upgrade-begin":
		ttl := contracts.DefaultUpgradeTTLSeconds
		if len(rest) > 0 {
			v, err := strconv.Atoi(rest[0])
			if err != nil || v <= 0 || v > contracts.MaxUpgradeTTLSeconds {
				return fmt.Errorf("invalid ttl %q", rest[0])
			}
			ttl = v
		}
		out, err := rpc.SendRootCtl(contracts.CtlSockPath, "upgrade-begin", strconv.Itoa(ttl))
		if err == nil {
			fmt.Println(out)
			return nil
		}
		if !isCtlDaemonUnavailable(err) {
			return err
		}
		bootID, err := sysio.ReadBootID()
		if err != nil {
			return err
		}
		fence := contracts.UpgradeFence{
			BootID: bootID, Active: true,
			UntilMonoNs: sysio.MonotonicNowNs() + int64(ttl)*int64(time.Second),
			TTLSeconds:  ttl,
		}
		b, _ := json.Marshal(fence)
		_ = sysio.WriteAtomic(contracts.UpgradeFencePath, append(b, '\n'), sysio.WriteAtomicOptions{Perm: 0600, UID: 0, GID: 0})
		_ = removeIfExist(contracts.SandboxAckPath)
		if p, err := ReadPolicy(); err == nil {
			spec := closedGateSpec(p, true)
			if err := nf.ApplyOrVerify(ctx, spec, false); err != nil {
				return err
			}
		}
		fmt.Printf("upgrading fence active ttl=%ds (offline)\n", ttl)
		return nil

	case "upgrade-end":
		out, err := rpc.SendRootCtl(contracts.CtlSockPath, "upgrade-end")
		if err == nil {
			fmt.Println(out)
			return nil
		}
		if !isCtlDaemonUnavailable(err) {
			return err
		}
		_ = removeIfExist(contracts.UpgradeFencePath)
		if p, err := ReadPolicy(); err == nil {
			extCap, _ := nf.DetectProxyCapture(ctx, p.ProxySkipPrefix)
			_ = nf.ApplyOrVerify(ctx, closedGateSpec(p, extCap), false)
		}
		fmt.Println("upgrading fence cleared (offline)")
		return nil

	case "bootstrap-pin":
		fs := flag.NewFlagSet("bootstrap-pin", flag.ContinueOnError)
		userFlag := fs.Int("user", 0, "work profile user id")
		serialFlag := fs.Int("serial", 0, "work profile serial")
		pkgFlag := fs.String("pkg", contracts.DefaultWorkPackage, "controller package name")
		adminFlag := fs.String("admin", "", "explicit DPC admin component pkg/class")
		serviceFlag := fs.String("service", "", "explicit VPN service component pkg/class")
		apkFlag := fs.String("apk", "", "explicit base.apk path")
		certFlag := fs.String("cert", "", "explicit sha256 cert")
		modeFlag := fs.String("mode", "", "sandbox transport mode: tproxy|vpn (default: keep pinned mode, else tproxy)")
		tpPortFlag := fs.Int("tproxy-port", 0, "tproxy port (default 1537)")
		tpMarkFlag := fs.Uint("tproxy-mark", 0, "tproxy fwmark (default 0x1a)")
		endpointFlag := fs.String("endpoint", "", "optional pinned IPv4 endpoint for VPN mode")
		endpointPortFlag := fs.Int("endpoint-port", contracts.EndpointPort, "endpoint port for VPN mode")
		portalDNSFlag := fs.String("portal-dns", contracts.PortalDNS4, "portal DNSv4 inside sandbox")
		proxyDirFlag := fs.String("proxy-dir", "", "optional external proxy base dir")
		proxySkipFlag := fs.String("proxy-skip-prefix", "", "optional external proxy iptables chain prefix")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		userID, serial := *userFlag, *serialFlag
		if userID == 0 || serial == 0 {
			prof, err := android.DiscoverManagedProfile(ctx, runner)
			if err != nil {
				return err
			}
			if userID == 0 {
				userID = prof.UserID
			}
			if serial == 0 {
				serial = prof.Serial
			}
		}
		if oem.IsForbiddenUser(userID) || serial <= 0 {
			return fmt.Errorf("invalid profile user=%d serial=%d", userID, serial)
		}
		pkg := strings.TrimSpace(*pkgFlag)
		if pkg == "" {
			pkg = contracts.DefaultWorkPackage
		}
		u0UID, discoveredAPK, err := android.DiscoverUser0Package(ctx, runner, pkg)
		if err != nil {
			return err
		}
		apkPath := discoveredAPK
		if *apkFlag != "" {
			apkPath = *apkFlag
		}
		certSHA := *certFlag
		if certSHA == "" {
			certSHA, err = apkcert.ExtractPrimaryCertSHA256(apkPath)
			if err != nil {
				return err
			}
		}
		policy := contracts.Policy{
			UserID:           userID,
			Serial:           serial,
			CallerPackage:    pkg,
			CallerCertSHA256: certSHA,
			AdminComponent:   strings.TrimSpace(*adminFlag),
			ServiceComponent: strings.TrimSpace(*serviceFlag),
			PortalDNS4:       strings.TrimSpace(*portalDNSFlag),
			EndpointV4:       strings.TrimSpace(*endpointFlag),
			EndpointPort:     *endpointPortFlag,
			IPv6Enabled:      false,
			Mode:             *modeFlag,
			TProxyPort:       *tpPortFlag,
			TProxyMark:       uint32(*tpMarkFlag),
			ProxyBaseDir:     strings.TrimSpace(*proxyDirFlag),
			ProxySkipPrefix:  strings.TrimSpace(*proxySkipFlag),
		}
		if policy.Mode == "" {
			if prev, perr := ReadPolicy(); perr == nil && prev.Mode != "" {
				policy.Mode = prev.Mode
				if policy.TProxyPort == 0 {
					policy.TProxyPort = prev.TProxyPort
				}
				if policy.TProxyMark == 0 {
					policy.TProxyMark = prev.TProxyMark
				}
				if policy.ProxyBaseDir == "" {
					policy.ProxyBaseDir = prev.ProxyBaseDir
				}
				if policy.ProxySkipPrefix == "" {
					policy.ProxySkipPrefix = prev.ProxySkipPrefix
				}
			} else {
				policy.Mode = contracts.ModeTProxy
			}
		}
		if policy.Mode == contracts.ModeVPN {
			policy.TProxyPort, policy.TProxyMark = 0, 0
		}
		if err := policy.NormalizeAndValidate(); err != nil {
			return err
		}
		pb, _ := json.MarshalIndent(policy, "", "  ")
		if err := sysio.WriteAtomic(contracts.PolicyPath, append(pb, '\n'), sysio.WriteAtomicOptions{Perm: 0600, UID: 0, GID: 0}); err != nil {
			return err
		}
		ensureDevDirs()
		ab, _ := json.Marshal(contracts.BrokerAuth{AllowedUser0UID: u0UID})
		_ = sysio.WriteAtomic(contracts.BrokerAuthPath, append(ab, '\n'), sysio.WriteAtomicOptions{
			Perm: 0600, UID: 0, GID: 0, SELinux: contracts.SELinuxPrivFile,
		})
		_, _ = rpc.SendRootCtl(contracts.CtlSockPath, "reload-policy")
		fmt.Println(string(pb))
		return nil

	case "variant-info":
		b, err := json.MarshalIndent(buildinfo.Current(), "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil

	case "preset-apply":
		if len(rest) != 1 {
			return errors.New("usage: preset-apply <preset.json>")
		}
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "preset-apply", rest[0]); err == nil {
			fmt.Println(out)
			return nil
		}
		dOff := &Daemon{
			runner:               runner,
			stealthConfigPath:    contracts.StealthConfigPath,
			stealthRuntimePath:   contracts.StealthRuntimePath,
			zygiskDisabledFlag:   contracts.ZygiskDisabledFlag,
			stealthBootTriesPath: contracts.StealthBootTriesPath,
		}
		if p, err := ReadPolicy(); err == nil {
			dOff.policy = p
			dOff.policyLoaded = true
		}
		cfg, err := dOff.ApplyPresetFile(ctx, rest[0])
		if err != nil {
			return err
		}
		b, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil

	case "status":
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "status"); err == nil {
			fmt.Println(out)
			return nil
		}
		p, err := ReadPolicy()
		if err != nil {
			return err
		}
		bootID, _ := sysio.ReadBootID()
		uidStart, uidEnd := p.UIDRange()
		spec := netfilter.GateSpec{
			UserID: p.UserID, UIDStart: uidStart, UIDEnd: uidEnd,
			PortalDNS4: p.PortalDNS4, EndpointV4: p.EndpointV4, EndpointPort: p.EndpointPort,
			IPv6Enabled: p.IPv6Enabled, ProxySkipPrefix: p.ProxySkipPrefix,
			Mode: p.Mode, TProxyPort: p.TProxyPort, TProxyMark: p.TProxyMark,
		}
		insp, err := nf.InspectRuntime(ctx, spec)
		if err != nil {
			return err
		}
		outObj := map[string]any{
			"daemon_running":   false,
			"variant":          buildinfo.Current(),
			"boot_id":          bootID,
			"user_id":          p.UserID,
			"serial":           p.Serial,
			"external_capture": insp.ExternalCapture,
			"sbw_raw_armed":    insp.RawArmed,
			"sbw_open":         insp.OutputOpen && insp.EgressOpen,
		}
		b, _ := json.MarshalIndent(outObj, "", "  ")
		fmt.Println(string(b))
		return nil

	case "sync-hide":
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "sync-hide"); err == nil {
			fmt.Println(out)
			return nil
		}
		p, err := ReadPolicy()
		if err != nil {
			return err
		}
		res, err := android.SyncHideApps(ctx, runner, p.UserID, p.Serial)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(res)
		fmt.Println(string(b))
		return nil

	case "pause-sandbox":
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "pause-sandbox"); err == nil {
			fmt.Println(out)
			return nil
		}
		return errors.New("sandbox_guard daemon not running")

	case "start-sandbox":
		out, err := rpc.SendRootCtl(contracts.CtlSockPath, "start-sandbox")
		if err != nil {
			return err
		}
		fmt.Println(out)
		return nil

	case "sync-policies":
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "sync-policies"); err == nil {
			fmt.Println(out)
			return nil
		}
		p, err := ReadPolicy()
		if err != nil {
			return err
		}
		dOff := &Daemon{runner: runner}
		res, err := dOff.syncPolicies(ctx, p)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(res)
		fmt.Println(string(b))
		return nil

	case "perf-status":
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "perf-status"); err == nil {
			fmt.Println(out)
			return nil
		}
		perf := LoadPerfConfig(contracts.PerfConfigPath)
		b, _ := json.MarshalIndent(perf, "", "  ")
		fmt.Println(string(b))
		return nil

	case "perf-trace":
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "perf-trace"); err == nil {
			fmt.Println(out)
			return nil
		}
		fmt.Println("[]")
		return nil

	case "pause-hot":
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "pause-hot"); err == nil {
			fmt.Println(out)
			return nil
		}
		return errors.New("sandbox_guard daemon not running")

	case "prune-bloat":
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "prune-bloat"); err == nil {
			fmt.Println(out)
			return nil
		}
		p, err := ReadPolicy()
		if err != nil {
			return err
		}
		res, err := android.PruneSandboxBloat(ctx, runner, p.UserID, contracts.PrunedPkgsPath, p.EffectiveCallerPackage())
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil

	case "restore-bloat":
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "restore-bloat"); err == nil {
			fmt.Println(out)
			return nil
		}
		p, err := ReadPolicy()
		if err != nil {
			return err
		}
		res, err := android.RestoreSandboxBloat(ctx, runner, p.UserID, contracts.PrunedPkgsPath)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
		return nil

	case "flush-sandbox-conns":
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "flush-sandbox-conns"); err == nil {
			fmt.Println(out)
			return nil
		}
		perf := LoadPerfConfig(contracts.PerfConfigPath)
		n, err := FlushSandboxConnections(ctx, contracts.MainConfigPath, perf.SandboxInboundName)
		if err != nil {
			return err
		}
		b, _ := json.Marshal(map[string]any{"inbound": perf.SandboxInboundName, "closed": n})
		fmt.Println(string(b))
		return nil

	case "set-app-locale":
		if len(rest) != 2 {
			return errors.New("usage: set-app-locale <package> <locale|clear>")
		}
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "set-app-locale", rest...); err == nil {
			fmt.Println(out)
			return nil
		}
		p, err := ReadPolicy()
		if err != nil {
			return err
		}
		if err := android.SetSandboxAppLocale(ctx, runner, p.UserID, rest[0], rest[1], p.EffectiveCallerPackage()); err != nil {
			return err
		}
		perf := LoadPerfConfig(contracts.PerfConfigPath)
		if perf.LocaleOverrides == nil {
			perf.LocaleOverrides = map[string]string{}
		}
		if strings.EqualFold(rest[1], "clear") || strings.EqualFold(rest[1], "none") {
			perf.LocaleOverrides[rest[0]] = ""
		} else {
			perf.LocaleOverrides[rest[0]] = rest[1]
		}
		_ = WritePerfConfig(contracts.PerfConfigPath, perf)
		b, _ := json.Marshal(map[string]any{"user_id": p.UserID, "package": rest[0], "locale": perf.LocaleOverrides[rest[0]]})
		fmt.Println(string(b))
		return nil

	case "install-apk":
		if len(rest) == 0 {
			return errors.New("install-apk requires at least 1 apk path")
		}
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "install-apk", rest...); err == nil {
			fmt.Println(out)
			return nil
		}
		p, err := ReadPolicy()
		if err != nil {
			return err
		}
		res, err := android.InstallSandboxAPKs(ctx, runner, p.UserID, rest, nil)
		if err != nil {
			return err
		}
		_, _ = android.SyncHideApps(ctx, runner, p.UserID, p.Serial)
		dOff := &Daemon{runner: runner}
		_, _ = dOff.syncPolicies(ctx, p)
		b, _ := json.Marshal(res)
		fmt.Println(string(b))
		return nil

	case "stealth-status":
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "stealth-status"); err == nil {
			fmt.Println(out)
			return nil
		}
		d := &Daemon{
			stealthConfigPath:    contracts.StealthConfigPath,
			stealthRuntimePath:   contracts.StealthRuntimePath,
			zygiskDisabledFlag:   contracts.ZygiskDisabledFlag,
			stealthBootTriesPath: contracts.StealthBootTriesPath,
		}
		b, _ := json.MarshalIndent(d.ReadStealthStatus(), "", "  ")
		fmt.Println(string(b))
		return nil

	case "stealth-toggle":
		if len(rest) != 1 || (rest[0] != "on" && rest[0] != "off") {
			return errors.New("usage: stealth-toggle on|off")
		}
		if out, err := rpc.SendRootCtl(contracts.CtlSockPath, "stealth-toggle", rest[0]); err == nil {
			fmt.Println(out)
			return nil
		}
		d := &Daemon{
			stealthConfigPath:    contracts.StealthConfigPath,
			stealthRuntimePath:   contracts.StealthRuntimePath,
			zygiskDisabledFlag:   contracts.ZygiskDisabledFlag,
			stealthBootTriesPath: contracts.StealthBootTriesPath,
		}
		if p, err := ReadPolicy(); err == nil {
			d.policy = p
			d.policyLoaded = true
		}
		cfg, err := d.ToggleStealth(rest[0] == "on")
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(b))
		return nil

	case "block":
		out, err := rpc.SendRootCtl(contracts.CtlSockPath, "block")
		if err == nil {
			fmt.Println(out)
			return nil
		}
		if !isCtlDaemonUnavailable(err) {
			return err
		}
		_ = SaveDesiredState(true)
		p, err := ReadPolicy()
		if err != nil {
			return err
		}
		bootID, _ := sysio.ReadBootID()
		var gen uint64 = 1
		if prev, err := ReadExemption(contracts.ExemptionPath); err == nil && prev.Generation >= 1 {
			gen = prev.Generation + 1
		}
		ex := BuildBlockedExemption(p, bootID, 0, gen)
		if b, err := json.Marshal(ex); err == nil {
			_ = sysio.WriteAtomic(contracts.ExemptionPath, append(b, '\n'), sysio.WriteAtomicOptions{Perm: 0600, UID: 0, GID: 0})
		}
		extCap, _ := nf.DetectProxyCapture(ctx, p.ProxySkipPrefix)
		if err := nf.ApplyOrVerify(ctx, closedGateSpec(p, extCap), false); err != nil {
			return err
		}
		fmt.Println("blocked")
		return nil

	default:
		return fmt.Errorf("unknown ctl subcommand %q", sub)
	}
}
