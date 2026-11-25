package android

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMainCoreAliveAndReadProcUID(t *testing.T) {
	tmp := t.TempDir()
	procRoot := filepath.Join(tmp, "proc")
	pidDir := filepath.Join(procRoot, "4242")
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(tmp, "core.pid")
	if err := os.WriteFile(pidFile, []byte("4242\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("/data/adb/sandbox_proxy/bin/mihomo\x00-d\x00/data/adb/sandbox_proxy\x00"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte("Name:\tmihomo\nUid:\t0\t0\t0\t0\n"), 0600); err != nil {
		t.Fatal(err)
	}

	pid, ok := mainCoreAliveFS(pidFile, "mihomo", procRoot)
	if !ok || pid != 4242 {
		t.Fatalf("expected pid 4242 ok=true, got pid=%d ok=%v", pid, ok)
	}
	if _, badOK := mainCoreAliveFS(pidFile, "sing-box", procRoot); badOK {
		t.Fatal("expected procHint mismatch to return false")
	}
	uid, uok := readProcUID(procRoot, 4242)
	if !uok || uid != 0 {
		t.Fatalf("expected uid=0 ok=true, got uid=%d ok=%v", uid, uok)
	}
}

func TestScanProcNetPortReaderUIDAndAddr(t *testing.T) {
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	allowed := map[int]bool{0: true}

	// Port 1537 = 0x0601
	spoofedUID := header + "   0: 0100007F:0601 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10123 0 999 1 00000000\n"
	if scanProcNetPortReader(strings.NewReader(spoofedUID), 1537, "0A", allowed) {
		t.Fatal("must reject listener owned by unprivileged UID 10123")
	}

	lanAddr := header + fmt.Sprintf("   0: 6401A8C0:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 999 1 00000000\n", 1537)
	if scanProcNetPortReader(strings.NewReader(lanAddr), 1537, "0A", allowed) {
		t.Fatal("must reject non-loopback/non-wildcard LAN local address")
	}

	loopV4 := header + fmt.Sprintf("   0: 0100007F:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 999 1 00000000\n", 1537)
	if !scanProcNetPortReader(strings.NewReader(loopV4), 1537, "0A", allowed) {
		t.Fatal("expected root 127.0.0.1 listener to succeed")
	}

	wildV6 := header + fmt.Sprintf("   0: 00000000000000000000000000000000:%04X 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 999 1 00000000\n", 1537)
	if !scanProcNetPortReader(strings.NewReader(wildV6), 1537, "07", allowed) {
		t.Fatal("expected root :: UDP socket to succeed")
	}
}
