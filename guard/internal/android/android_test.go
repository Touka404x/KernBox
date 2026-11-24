package android

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
)

type fakeRunner struct {
	outputs map[string]string
}

func (f fakeRunner) Run(ctx context.Context, timeout time.Duration, stdin string, name string, args ...string) (string, error) {
	key := name + " " + strings.Join(args, " ")
	if out, ok := f.outputs[key]; ok {
		return out, nil
	}
	return "", errors.New("unmocked cmd: " + key)
}

func TestDiscoverManagedProfileRejects999(t *testing.T) {
	// Android 13+ `cmd user list -v` output with a managed profile and clone user 999
	r := fakeRunner{outputs: map[string]string{
		"cmd user list -v": `3 users:
0: id=0, name=Owner, type=full.SYSTEM, flags=PRIMARY|ADMIN|FULL|INITIALIZED (running) (current)
1: id=10, name=Work Sandbox, type=profile.MANAGED, flags=INITIALIZED|MANAGED_PROFILE|PROFILE (parentId=0) (running) (profile-owner)
2: id=999, name=XSpace, type=profile.CLONE, flags=INITIALIZED|PROFILE (parentId=0) (running)
`,
		"dumpsys user --user 10": "  UserInfo{10:Work Sandbox:1030} serialNo=1000 isPrimary=false parentId=0\n    Type: android.os.usertype.profile.MANAGED\n    Flags: 4144 (INITIALIZED|MANAGED_PROFILE|PROFILE)\n    State: RUNNING_UNLOCKED\n",
	}}
	prof, err := DiscoverManagedProfile(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if prof.UserID != 10 || prof.Serial != 1000 {
		t.Fatalf("unexpected profile: %+v", prof)
	}

	// If only user 999 exists, must fail.
	rOnly999 := fakeRunner{outputs: map[string]string{
		"cmd user list -v": "  2: id=999, name=XSpace, type=profile.CLONE, flags=INITIALIZED|PROFILE (parentId=0) (running)\n",
	}}
	if _, err := DiscoverManagedProfile(context.Background(), rOnly999); err == nil {
		t.Fatal("accepted user 999")
	}

	// Non-zero parentId must also be rejected.
	rWrongParent := fakeRunner{outputs: map[string]string{
		"cmd user list -v": "  1: id=11, name=Nested, type=profile.MANAGED, flags=INITIALIZED|MANAGED_PROFILE|PROFILE (parentId=10) (running)\n",
	}}
	if _, err := DiscoverManagedProfile(context.Background(), rWrongParent); err == nil {
		t.Fatal("accepted non-zero parentId")
	}
}

func TestTryFastSingleUplinkVsDualUplink(t *testing.T) {
	status := &contracts.VPNStatus{
		BootID:        "boot-1",
		Running:       true,
		TunIf:         "tun0",
		VPNNetID:      106,
		UnderlayIf:    "wlan0",
		UnderlayNetID: 100,
	}
	tun := LiveIface{Name: "tun0", Index: 19, Up: true, HasIPv4: true, IPv4CIDRs: []string{"172.19.0.1/30"}}
	wlan := LiveIface{Name: "wlan0", Index: 12, Up: true, HasIPv4: true, IPv4CIDRs: []string{"192.168.1.10/24"}}
	cell := LiveIface{Name: "ccmni2", Index: 8, Up: true, HasIPv4: true, IPv4CIDRs: []string{"10.1.2.3/24"}}

	// Single uplink fast path succeeds without dumpsys.
	sess, multi, ok := TryFastSingleUplinkSession("boot-1", 1010376, status, []LiveIface{tun, wlan})
	if !ok || multi || sess == nil || sess.UplinkIf != "wlan0" || sess.UplinkNetID != 100 {
		t.Fatalf("expected fast single uplink success, got sess=%+v multi=%v ok=%v", sess, multi, ok)
	}

	// Legacy single-uplink helper still reports multi=true when both uplinks exist.
	sess2, multi2, ok2 := TryFastSingleUplinkSession("boot-1", 1010376, status, []LiveIface{tun, wlan, cell})
	if ok2 || !multi2 || sess2 != nil {
		t.Fatalf("expected legacy single-uplink helper multi=true, got sess=%+v multi=%v ok=%v", sess2, multi2, ok2)
	}

	// New TryFastStatusSession resolves directly during dual-uplink coexistence without dumpsys.
	sessDualWifi, okDualWifi := TryFastStatusSession("boot-1", 1010376, status, []LiveIface{tun, wlan, cell})
	if !okDualWifi || sessDualWifi == nil || sessDualWifi.UplinkIf != "wlan0" || sessDualWifi.UplinkIndex != 12 || sessDualWifi.UplinkNetID != 100 {
		t.Fatalf("expected dual-uplink fast status resolution for wlan0, got sess=%+v ok=%v", sessDualWifi, okDualWifi)
	}
	cellStatus := *status
	cellStatus.UnderlayIf = "ccmni2"
	cellStatus.UnderlayNetID = 101
	sessDualCell, okDualCell := TryFastStatusSession("boot-1", 1010376, &cellStatus, []LiveIface{tun, wlan, cell})
	if !okDualCell || sessDualCell == nil || sessDualCell.UplinkIf != "ccmni2" || sessDualCell.UplinkIndex != 8 || sessDualCell.UplinkNetID != 101 {
		t.Fatalf("expected dual-uplink fast status resolution for ccmni2, got sess=%+v ok=%v", sessDualCell, okDualCell)
	}

	// Reject loopback, tun-as-underlay, missing interface, or low net_id.
	for _, bad := range []struct {
		ifName string
		netID  int
	}{
		{"lo", 100},
		{"tun0", 100},
		{"wlan99", 100},
		{"wlan0", 99},
	} {
		bs := *status
		bs.UnderlayIf = bad.ifName
		bs.UnderlayNetID = bad.netID
		if s, ok := TryFastStatusSession("boot-1", 1010376, &bs, []LiveIface{tun, wlan, cell}); ok || s != nil {
			t.Fatalf("expected fast status rejection for %+v, got %+v", bad, s)
		}
	}
}

func TestParseWorkNetworks(t *testing.T) {
	const dump = `Current Networks:
  NetworkAgentInfo{network{100}  handle{4294967296}  ni{MOBILE[NR] CONNECTED extra: cmnet}  lp{{InterfaceName: ccmni2 LinkAddresses: [ 10.0.0.1/24 ] }}  nc{[ Transports: CELLULAR ]}}
  NetworkAgentInfo{network{101}  handle{4294967297}  ni{WIFI CONNECTED extra: ssid}  lp{{InterfaceName: wlan0 LinkAddresses: [ 192.168.1.2/24 ] }}  nc{[ Transports: WIFI ]}}
  NetworkAgentInfo{network{106}  handle{4294967298}  ni{VPN CONNECTED extra: }  lp{{InterfaceName: tun0 LinkAddresses: [ 172.19.0.1/30 ] DnsAddresses: [ /172.19.0.2 ] }}  nc{[ Transports: CELLULAR|VPN Uids: <{1000000-1099999}> OwnerUid: 1010376 AdminUids: [1010376] UnderlyingNetworks: [100]]}  factorySerialNumber=-1}
`

	s, err := ParseWorkNetworks(dump, 1010376)
	if err != nil {
		t.Fatal(err)
	}
	if s.VPNNetID != 106 || s.UplinkNetID != 100 || s.UplinkIf != "ccmni2" || s.TunIf != "tun0" {
		t.Fatalf("unexpected parsed session: %+v", s)
	}
}

func TestVerifyStaticIdentityAndDPC(t *testing.T) {
	pkg := contracts.DefaultWorkPackage
	adminComp := contracts.DefaultAdminComponent
	r := fakeRunner{outputs: map[string]string{
		"cmd user list -v": `3 users:
0: id=0, name=Owner, type=full.SYSTEM, flags=PRIMARY|ADMIN|FULL|INITIALIZED (running) (current)
1: id=10, name=Work Sandbox, type=profile.MANAGED, flags=INITIALIZED|MANAGED_PROFILE|PROFILE (parentId=0) (running) (profile-owner)
2: id=999, name=XSpace, type=profile.CLONE, flags=INITIALIZED|PROFILE (parentId=0) (running)
`,
		"dumpsys user --user 10":                                       "  UserInfo{10:Work Sandbox:1030} serialNo=1000 isPrimary=false parentId=0\n    Type: android.os.usertype.profile.MANAGED\n    Flags: 4144 (INITIALIZED|MANAGED_PROFILE|PROFILE)\n    State: RUNNING_UNLOCKED\n",
		"cmd device_policy list-owners":                                "User 10: admin=" + adminComp + ",ProfileOwner\nUser 10: admin=" + adminComp + ",ManagedProfileOwner(parentUserId=0)\n",
		"settings --user 10 get secure always_on_vpn_app":              pkg + "\n",
		"settings --user 10 get secure always_on_vpn_lockdown":         "1\n",
		"settings --user 10 get secure always_on_vpn_lockdown_whitelist": "null\n",
		"dumpsys vpn_management":                                       "  0: null\n  10: " + pkg + "\n",
		"cmd package list packages --user 10 -U " + pkg:                "package:" + pkg + " uid:1010376\n",
	}}
	pol := contracts.Policy{
		UserID:           10,
		Serial:           1000,
		CallerPackage:    pkg,
		CallerCertSHA256: strings.Repeat("a", 64),
	}
	id, err := VerifyStaticIdentity(context.Background(), r, pol)
	if err != nil {
		t.Fatalf("VerifyStaticIdentity failed: %v", err)
	}
	if id.UserID != 10 || id.Serial != 1000 || id.ClientUID != 1010376 {
		t.Fatalf("unexpected VerifiedIdentity: %+v", id)
	}
	// Reject user 0 and OEM excluded clone users
	for _, badUser := range append([]int{0}, oem.Current().ExcludedCloneUsers...) {
		badPol := pol
		badPol.UserID = badUser
		if _, err := VerifyStaticIdentity(context.Background(), r, badPol); err == nil {
			t.Fatalf("accepted forbidden user %d", badUser)
		}
	}
}

type fakeCgroupFS struct {
	files map[string][]byte
}

func (f *fakeCgroupFS) ReadFile(p string) ([]byte, error) {
	if b, ok := f.files[p]; ok {
		return b, nil
	}
	return nil, errors.New("not found")
}

func (f *fakeCgroupFS) WriteFile(p string, b []byte) error {
	f.files[p] = append([]byte(nil), b...)
	return nil
}

func TestMilletCgroupV2FreezeAndUnfreeze(t *testing.T) {
	fs := &fakeCgroupFS{files: map[string][]byte{
		"/sys/fs/cgroup/uid_1010376/pid_6206/cgroup.freeze": []byte("1\n"),
		"/sys/fs/cgroup/frozen/cgroup.procs":                []byte("123\n6206\n"),
		"/sys/fs/cgroup/freezer/cgroup.procs":               []byte("must_never_read"),
	}}
	st := InspectCgroupV2Freeze(fs, 1010376, 6206)
	if !st.Frozen || st.FreezePath != "/sys/fs/cgroup/uid_1010376/pid_6206/cgroup.freeze" {
		t.Fatalf("failed to detect cgroup v2 freeze: %+v", st)
	}
	st.InFrozenGroup = true
	if err := UnfreezeCgroupV2(fs, 1010376, 6206, st); err != nil {
		t.Fatal(err)
	}
	if string(fs.files["/sys/fs/cgroup/uid_1010376/pid_6206/cgroup.freeze"]) != "0" {
		t.Fatal("failed to write 0 to cgroup.freeze")
	}
	if string(fs.files["/sys/fs/cgroup/unfrozen/cgroup.procs"]) != "6206" {
		t.Fatal("failed to move pid to unfrozen/cgroup.procs")
	}
}
