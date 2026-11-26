package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/rpc"
	"sandbox_guard/internal/sysio"
)

type PeerCheckFunc func(conn net.Conn) (sysio.PeerCredentials, error)

type BrokerConfig struct {
	ClientSockPath string
	GuardSockPath  string
	AuthFilePath   string
	AttrPath       string
	AllowTestCtx   bool
	GetPeerCreds   PeerCheckFunc
}

func DefaultBrokerConfig() BrokerConfig {
	return BrokerConfig{
		ClientSockPath: contracts.BrokerSockPath,
		GuardSockPath:  contracts.GuardSockPath,
		AuthFilePath:   contracts.BrokerAuthPath,
		AttrPath:       contracts.ProcSelfAttrCurrent,
		AllowTestCtx:   false,
		GetPeerCreds:   sysio.GetUnixPeerCreds,
	}
}

// CheckSelfContext reads /proc/self/attr/current and enforces u:r:sandbox_broker:s0
// unless allowTest is explicitly enabled outside production.
func CheckSelfContext(attrPath string, allowTest bool) (string, error) {
	if allowTest {
		return "test-context", nil
	}
	data, err := os.ReadFile(attrPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", attrPath, err)
	}
	ctx := strings.TrimSpace(strings.TrimRight(string(data), "\x00"))
	if ctx != contracts.SELinuxBrokerCtx {
		return ctx, fmt.Errorf("unexpected SELinux context %q, want %q", ctx, contracts.SELinuxBrokerCtx)
	}
	return ctx, nil
}

// AuthorizePeer enforces SO_PEERCRED (uid == allowed_user0_uid && uid < 100000)
// and SO_PEERSEC (u:r:untrusted_app*, rejecting isolated_app).
func AuthorizePeer(creds sysio.PeerCredentials, allowedUser0UID int) error {
	if !contracts.ValidUser0AppUID(allowedUser0UID) {
		return errors.New("no valid allowed_user0_uid configured")
	}
	if creds.UID != allowedUser0UID || creds.UID < contracts.MinAppID || creds.UID >= contracts.AndroidUserWidth {
		return fmt.Errorf("unauthorized peer uid %d (want %d)", creds.UID, allowedUser0UID)
	}
	ctx := strings.TrimSpace(strings.TrimRight(creds.Context, "\x00"))
	parts := strings.Split(ctx, ":")
	if len(parts) < 3 || parts[0] != "u" || parts[1] != "r" {
		return fmt.Errorf("malformed peer SELinux context %q", ctx)
	}
	domain := parts[2]
	if strings.Contains(ctx, "isolated_app") || !strings.HasPrefix(domain, "untrusted_app") {
		return fmt.Errorf("rejected peer SELinux context %q", ctx)
	}
	return nil
}

func ReadBrokerAuth(path string) (contracts.BrokerAuth, error) {
	data, err := sysio.ReadRootOwnedSmallFile(path, 1024)
	if err != nil {
		return contracts.BrokerAuth{}, err
	}
	var auth contracts.BrokerAuth
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&auth); err != nil {
		return contracts.BrokerAuth{}, err
	}
	return auth, nil
}

func ServeBroker(cfg BrokerConfig) (net.Listener, func(), error) {
	if _, err := CheckSelfContext(cfg.AttrPath, cfg.AllowTestCtx); err != nil {
		return nil, nil, err
	}
	if cfg.GetPeerCreds == nil {
		cfg.GetPeerCreds = sysio.GetUnixPeerCreds
	}

	_ = os.Remove(cfg.ClientSockPath)
	oldMask := sysio.SetUmask(0000)
	ln, err := net.Listen("unix", cfg.ClientSockPath)
	sysio.SetUmask(oldMask)
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(cfg.ClientSockPath, 0666); err != nil {
		_ = ln.Close()
		_ = os.Remove(cfg.ClientSockPath)
		return nil, nil, err
	}

	stop := func() {
		_ = ln.Close()
		_ = os.Remove(cfg.ClientSockPath)
	}
	sem := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case sem <- struct{}{}:
				go func(c net.Conn) {
					defer func() { <-sem }()
					handleBrokerConn(c, cfg)
				}(conn)
			default:
				_ = conn.Close()
			}
		}
	}()
	return ln, stop, nil
}

func handleBrokerConn(conn net.Conn, cfg BrokerConfig) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(36 * time.Second))

	creds, err := cfg.GetPeerCreds(conn)
	if err != nil {
		return
	}
	auth, err := ReadBrokerAuth(cfg.AuthFilePath)
	if err != nil {
		return
	}
	if err := AuthorizePeer(creds, auth.AllowedUser0UID); err != nil {
		return
	}

	line, err := rpc.ReadLineBounded(conn, contracts.MaxRPCLineBytes)
	if err != nil {
		writeBrokerErr(conn, "", err.Error())
		return
	}
	req, err := rpc.ParseAndValidateRequest(line)
	if err != nil {
		writeBrokerErr(conn, "", err.Error())
		return
	}

	if req.Op == contracts.OpInstallApk {
		_ = conn.SetDeadline(time.Now().Add(125 * time.Second))
	}

	payload := append(bytes.TrimSpace(line), '\n')
	if len(payload) > contracts.MaxRPCLineBytes {
		writeBrokerErr(conn, req.ID, fmt.Sprintf("request exceeds %d bytes", contracts.MaxRPCLineBytes))
		return
	}

	upstream, err := net.DialTimeout("unix", cfg.GuardSockPath, 3*time.Second)
	if err != nil {
		writeBrokerErr(conn, req.ID, "guard unavailable")
		return
	}
	defer upstream.Close()
	upDeadline := 33 * time.Second
	if req.Op == contracts.OpInstallApk {
		upDeadline = 125 * time.Second
	}
	_ = upstream.SetDeadline(time.Now().Add(upDeadline))

	if _, err := upstream.Write(payload); err != nil {
		writeBrokerErr(conn, req.ID, "guard write failed")
		return
	}
	respLine, err := rpc.ReadLineBounded(upstream, contracts.MaxRPCRespBytes)
	if err != nil {
		writeBrokerErr(conn, req.ID, "guard read failed")
		return
	}
	_, _ = conn.Write(append(bytes.TrimSpace(respLine), '\n'))
}

func writeBrokerErr(conn net.Conn, id, msg string) {
	b, _ := json.Marshal(contracts.RPCResponse{
		ID:    id,
		OK:    false,
		Error: msg,
		Data:  map[string]any{},
	})
	_, _ = conn.Write(append(b, '\n'))
}

func main() {
	runtime.GOMAXPROCS(1)
	debug.SetGCPercent(25)
	debug.SetMemoryLimit(3 << 20)
	cfg := DefaultBrokerConfig()

	_, stop, err := ServeBroker(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer stop()

	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	signal.Ignore(syscall.SIGHUP)
	<-sigs
}
