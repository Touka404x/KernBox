package android

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"sandbox_guard/internal/contracts"
)

// MainCoreAlive validates corePIDPath against /proc/<pid>/cmdline containing procHint
// (or any supported proxy core binary when procHint is empty). Pure Go, zero fork.
func MainCoreAlive(corePIDPath, procHint string) (int, bool) {
	return mainCoreAliveFS(corePIDPath, procHint, "/proc")
}

func mainCoreAliveFS(corePIDPath, procHint, procRoot string) (int, bool) {
	if corePIDPath == "" {
		corePIDPath = contracts.MainCorePIDPath
	}
	data, err := os.ReadFile(corePIDPath)
	if err != nil || len(data) > 32 {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0, false
	}
	cmd, err := os.ReadFile(fmt.Sprintf("%s/%d/cmdline", procRoot, pid))
	if err != nil {
		return 0, false
	}
	cmdLower := strings.ToLower(string(cmd))
	if hint := strings.ToLower(strings.TrimSpace(procHint)); hint != "" {
		if !strings.Contains(cmdLower, hint) {
			return 0, false
		}
		return pid, true
	}
	for _, known := range []string{"mihomo", "sing-box", "clash", "xray"} {
		if strings.Contains(cmdLower, known) {
			return pid, true
		}
	}
	return 0, false
}

// IsLocalPortListening scans IPv4 and IPv6 procfs for a local TCP LISTEN (st=0A) or UDP bound (st=07) socket
// on the given port. mihomo "listen: ::" dual-stack sockets appear under tcp6/udp6.
func IsLocalPortListening(port int) (tcpOK, udpOK bool) {
	return isLocalPortListeningFS(port, "/proc/net")
}

func isLocalPortListeningFS(port int, netRoot string) (tcpOK, udpOK bool) {
	for _, f := range []string{"tcp", "tcp6"} {
		if scanProcNetPort(netRoot+"/"+f, port, "0A") {
			tcpOK = true
			break
		}
	}
	for _, f := range []string{"udp", "udp6"} {
		if scanProcNetPort(netRoot+"/"+f, port, "07") {
			udpOK = true
			break
		}
	}
	return
}

func scanProcNetPort(path string, port int, wantState string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return scanProcNetPortReader(f, port, wantState)
}

func scanProcNetPortReader(r io.Reader, port int, wantState string) bool {
	wantPort := fmt.Sprintf("%04X", port)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		local := fields[1]
		idx := strings.LastIndexByte(local, ':')
		if idx < 0 || !strings.EqualFold(local[idx+1:], wantPort) {
			continue
		}
		if fields[3] == wantState {
			return true
		}
	}
	return false
}

// TProxyReadyProbe reports whether the proxy core is alive and listening on the sandbox TProxy port (tcp+udp).
func TProxyReadyProbe(port int, corePIDPath, procHint string) bool {
	if _, ok := MainCoreAlive(corePIDPath, procHint); !ok {
		return false
	}
	tcpOK, udpOK := IsLocalPortListening(port)
	return tcpOK && udpOK
}
