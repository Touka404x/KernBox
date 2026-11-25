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

func readProcUID(procRoot string, pid int) (int, bool) {
	data, err := os.ReadFile(fmt.Sprintf("%s/%d/status", procRoot, pid))
	if err != nil {
		return 0, false
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line[4:])
		if len(fields) == 0 {
			return 0, false
		}
		uid, err := strconv.Atoi(fields[0])
		if err != nil || uid < 0 {
			return 0, false
		}
		return uid, true
	}
	return 0, false
}

// IsLocalPortListening scans IPv4 and IPv6 procfs for a local TCP LISTEN (st=0A) or UDP bound (st=07) socket
// on the given port. mihomo "listen: ::" dual-stack sockets appear under tcp6/udp6.
func IsLocalPortListening(port int) (tcpOK, udpOK bool) {
	return isLocalPortListeningForUIDsFS(port, "/proc/net", nil)
}

func isLocalPortListeningFS(port int, netRoot string) (tcpOK, udpOK bool) {
	return isLocalPortListeningForUIDsFS(port, netRoot, nil)
}

func isLocalPortListeningForUIDsFS(port int, netRoot string, allowedUIDs map[int]bool) (tcpOK, udpOK bool) {
	for _, f := range []string{"tcp", "tcp6"} {
		if scanProcNetPort(netRoot+"/"+f, port, "0A", allowedUIDs) {
			tcpOK = true
			break
		}
	}
	for _, f := range []string{"udp", "udp6"} {
		if scanProcNetPort(netRoot+"/"+f, port, "07", allowedUIDs) {
			udpOK = true
			break
		}
	}
	return
}

func scanProcNetPort(path string, port int, wantState string, allowedUIDs map[int]bool) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return scanProcNetPortReader(f, port, wantState, allowedUIDs)
}

func isLoopbackOrWildcardProcAddr(hexAddr string) bool {
	switch strings.ToUpper(strings.TrimSpace(hexAddr)) {
	case "00000000",
		"0100007F",
		"00000000000000000000000000000000",
		"00000000000000000000000001000000",
		"0000000000000000FFFF000000000000",
		"0000000000000000FFFF00000100007F":
		return true
	default:
		return false
	}
}

func scanProcNetPortReader(r io.Reader, port int, wantState string, allowedUIDs map[int]bool) bool {
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
		if idx <= 0 || !strings.EqualFold(local[idx+1:], wantPort) {
			continue
		}
		if fields[3] != wantState {
			continue
		}
		if !isLoopbackOrWildcardProcAddr(local[:idx]) {
			continue
		}
		if allowedUIDs != nil {
			if len(fields) < 8 {
				continue
			}
			uid, err := strconv.Atoi(fields[7])
			if err != nil || !allowedUIDs[uid] {
				continue
			}
		}
		return true
	}
	return false
}

// TProxyReadyProbe reports whether the proxy core is alive and listening on the sandbox TProxy port (tcp+udp).
func TProxyReadyProbe(port int, corePIDPath, procHint string) bool {
	pid, ok := MainCoreAlive(corePIDPath, procHint)
	if !ok {
		return false
	}
	allowed := map[int]bool{0: true}
	if uid, ok := readProcUID("/proc", pid); ok {
		allowed[uid] = true
	}
	tcpOK, udpOK := isLocalPortListeningForUIDsFS(port, "/proc/net", allowed)
	return tcpOK && udpOK
}
