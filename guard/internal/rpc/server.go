package rpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/sysio"
)

type Handler interface {
	HandleRPC(ctx context.Context, req contracts.RPCRequest) contracts.RPCResponse
}

type CtlHandler interface {
	HandleCtl(ctx context.Context, cmd string, args []string) (string, error)
}

var allowedOps = map[string]bool{
	contracts.OpGetStatus:      true,
	contracts.OpImportExisting: true,
	contracts.OpInstallApk:     true,
	contracts.OpStartVPN:       true,
	contracts.OpPauseVPN:       true,
	contracts.OpReloadConfig:   true,
	contracts.OpSyncHideApps:   true,
	contracts.OpRunProbe:       true,
	contracts.OpLaunchApp:      true,
	contracts.OpStopApp:        true,
	contracts.OpRemoveApp:      true,
}

func IsSafeAPKPath(p string) bool {
	if len(p) == 0 || len(p) > 512 {
		return false
	}
	if !strings.HasSuffix(p, ".apk") {
		return false
	}
	if strings.Contains(p, "..") || strings.ContainsAny(p, "\x00\r\n\t;&|$`'\"\\ ") {
		return false
	}
	return strings.HasPrefix(p, "/data/local/tmp/") || strings.HasPrefix(p, contracts.StagingDir+"/")
}

// ParseAndValidateRequest enforces the frozen max-8192B newline-JSON RPC schema
// and strict package regex validation.
func ParseAndValidateRequest(rawLine []byte) (contracts.RPCRequest, error) {
	trimmed := bytes.TrimSpace(rawLine)
	if len(trimmed) == 0 {
		return contracts.RPCRequest{}, errors.New("empty request")
	}
	if len(rawLine) > contracts.MaxRPCLineBytes {
		return contracts.RPCRequest{}, fmt.Errorf("request exceeds %d bytes", contracts.MaxRPCLineBytes)
	}
	var req contracts.RPCRequest
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return contracts.RPCRequest{}, fmt.Errorf("invalid json: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return contracts.RPCRequest{}, errors.New("trailing data after json object")
	}
	if req.ID == "" || len(req.ID) > 128 || strings.ContainsAny(req.ID, "\r\n\t") {
		return contracts.RPCRequest{}, errors.New("invalid request id")
	}
	if !allowedOps[req.Op] {
		return contracts.RPCRequest{}, fmt.Errorf("unsupported op %q", req.Op)
	}
	if req.Op == contracts.OpImportExisting || req.Op == contracts.OpLaunchApp ||
		req.Op == contracts.OpStopApp || req.Op == contracts.OpRemoveApp {
		if !contracts.ValidPackageName(req.Pkg) {
			return contracts.RPCRequest{}, fmt.Errorf("invalid package name %q", req.Pkg)
		}
	} else if req.Pkg != "" && !contracts.ValidPackageName(req.Pkg) {
		return contracts.RPCRequest{}, fmt.Errorf("invalid package name %q", req.Pkg)
	}
	if req.Activity != "" {
		if req.Op != contracts.OpLaunchApp {
			return contracts.RPCRequest{}, errors.New("activity field only allowed on LAUNCH_APP")
		}
		if !contracts.ValidComponentClass(req.Activity) {
			return contracts.RPCRequest{}, fmt.Errorf("invalid activity class %q", req.Activity)
		}
	}
	if req.Op == contracts.OpInstallApk {
		if len(req.ApkPaths) == 0 || len(req.ApkPaths) > 32 {
			return contracts.RPCRequest{}, errors.New("INSTALL_APK requires 1..32 apk_paths")
		}
		for _, p := range req.ApkPaths {
			if !IsSafeAPKPath(p) {
				return contracts.RPCRequest{}, fmt.Errorf("unsafe apk_path %q", p)
			}
		}
	} else if len(req.ApkPaths) > 0 {
		return contracts.RPCRequest{}, errors.New("apk_paths only allowed on INSTALL_APK")
	}
	if req.Config != nil {
		if req.Op != contracts.OpReloadConfig {
			return contracts.RPCRequest{}, errors.New("config field only allowed on RELOAD_CONFIG")
		}
		if err := ValidateConfigOverrides(req.Config); err != nil {
			return contracts.RPCRequest{}, err
		}
	}
	return req, nil
}

func ValidateConfigOverrides(cfg *contracts.RPCConfigOverrides) error {
	if cfg == nil {
		return nil
	}
	if cfg.QuicUDP443Mode != "" && cfg.QuicUDP443Mode != "reject" && cfg.QuicUDP443Mode != "allow" {
		return fmt.Errorf("invalid quic_udp443_mode %q", cfg.QuicUDP443Mode)
	}
	switch cfg.LogLevel {
	case "", "silent", "error", "warning", "info", "debug":
	default:
		return fmt.Errorf("invalid log_level %q", cfg.LogLevel)
	}
	return nil
}

// ReadLineBounded reads a single newline-terminated line up to maxBytes without buffering unbounded memory.
func ReadLineBounded(r io.Reader, maxBytes int) ([]byte, error) {
	br := bufio.NewReaderSize(io.LimitReader(r, int64(maxBytes)+1), maxBytes+1)
	line, err := br.ReadBytes('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) > 0 {
			if len(line) > maxBytes {
				return nil, fmt.Errorf("line exceeds %d bytes", maxBytes)
			}
			return line, nil
		}
		return nil, err
	}
	if len(line) > maxBytes {
		return nil, fmt.Errorf("line exceeds %d bytes", maxBytes)
	}
	return line, nil
}

// ListenUnixSecured creates a Unix stream listener with deterministic permissions and optional SELinux label.
func ListenUnixSecured(sockPath string, perm os.FileMode, seCtx string) (net.Listener, error) {
	_ = os.Remove(sockPath)
	oldMask := sysio.SetUmask(0077)
	ln, err := net.Listen("unix", sockPath)
	sysio.SetUmask(oldMask)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sockPath, perm); err != nil {
		_ = ln.Close()
		_ = os.Remove(sockPath)
		return nil, err
	}
	if seCtx != "" {
		if err := sysio.Lsetfilecon(sockPath, seCtx); err != nil {
			_ = ln.Close()
			_ = os.Remove(sockPath)
			return nil, err
		}
	}
	return ln, nil
}

func authorizeUnixPeer(conn net.Conn, sockPath, wantCtx string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	creds, err := sysio.GetUnixPeerCreds(conn)
	if err != nil {
		return err
	}
	if strings.HasPrefix(sockPath, "/dev/") {
		if creds.UID != 0 {
			return fmt.Errorf("unauthorized uid %d on %s", creds.UID, sockPath)
		}
		peerCtx := strings.TrimSpace(strings.TrimRight(creds.Context, "\x00"))
		if wantCtx != "" && peerCtx != wantCtx {
			return fmt.Errorf("unauthorized peer context %q on %s", peerCtx, sockPath)
		}
		return nil
	}
	// Non-/dev test listeners only accept same-user (or root) peer credentials.
	if creds.UID != 0 && creds.UID != os.Getuid() {
		return fmt.Errorf("unauthorized uid %d on %s", creds.UID, sockPath)
	}
	return nil
}

func ServeGuardRPC(ctx context.Context, sockPath string, handler Handler) (func(), error) {
	ln, err := ListenUnixSecured(sockPath, 0600, contracts.SELinuxPrivSock)
	if err != nil {
		return nil, err
	}
	sem := make(chan struct{}, 16)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
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
					if aerr := authorizeUnixPeer(c, sockPath, contracts.SELinuxBrokerCtx); aerr != nil {
						_ = c.Close()
						return
					}
					handleGuardConn(ctx, c, handler)
				}(conn)
			default:
				_ = conn.Close()
			}
		}
	}()
	return func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	}, nil
}

func handleGuardConn(parent context.Context, conn net.Conn, handler Handler) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(36 * time.Second))

	line, err := ReadLineBounded(conn, contracts.MaxRPCLineBytes)
	if err != nil {
		writeResp(conn, contracts.RPCResponse{OK: false, Error: err.Error(), Data: map[string]any{}})
		return
	}
	req, err := ParseAndValidateRequest(line)
	if err != nil {
		writeResp(conn, contracts.RPCResponse{OK: false, Error: err.Error(), Data: map[string]any{}})
		return
	}
	cctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	resp := handler.HandleRPC(cctx, req)
	if resp.ID == "" {
		resp.ID = req.ID
	}
	if resp.Data == nil {
		resp.Data = map[string]any{}
	}
	writeResp(conn, resp)
}

func writeResp(conn net.Conn, resp contracts.RPCResponse) {
	b, err := json.Marshal(resp)
	if err != nil {
		b = []byte(`{"id":"","ok":false,"error":"marshal error","data":{}}`)
	}
	b = append(b, '\n')
	_, _ = conn.Write(b)
}

type CtlRequest struct {
	Cmd  string   `json:"cmd"`
	Args []string `json:"args,omitempty"`
}

type CtlResponse struct {
	OK     bool   `json:"ok"`
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

func ServeRootCtl(ctx context.Context, sockPath string, handler CtlHandler) (func(), error) {
	ln, err := ListenUnixSecured(sockPath, 0600, "")
	if err != nil {
		return nil, err
	}
	sem := make(chan struct{}, 16)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
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
					defer c.Close()
					if aerr := authorizeUnixPeer(c, sockPath, ""); aerr != nil {
						return
					}
					_ = c.SetDeadline(time.Now().Add(30 * time.Second))
					line, err := ReadLineBounded(c, contracts.MaxRPCLineBytes)
					if err != nil {
						_ = json.NewEncoder(c).Encode(CtlResponse{OK: false, Error: err.Error()})
						return
					}
					var req CtlRequest
					if err := json.Unmarshal(bytes.TrimSpace(line), &req); err != nil {
						_ = json.NewEncoder(c).Encode(CtlResponse{OK: false, Error: err.Error()})
						return
					}
					cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
					defer cancel()
					out, err := handler.HandleCtl(cctx, req.Cmd, req.Args)
					if err != nil {
						_ = json.NewEncoder(c).Encode(CtlResponse{OK: false, Error: err.Error()})
						return
					}
					_ = json.NewEncoder(c).Encode(CtlResponse{OK: true, Output: out})
				}(conn)
			default:
				_ = conn.Close()
			}
		}
	}()
	return func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	}, nil
}

func SendRootCtl(sockPath, cmd string, args ...string) (string, error) {
	conn, err := net.DialTimeout("unix", sockPath, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	b, err := json.Marshal(CtlRequest{Cmd: cmd, Args: args})
	if err != nil {
		return "", err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return "", err
	}
	line, err := ReadLineBounded(conn, contracts.MaxRPCRespBytes)
	if err != nil {
		return "", err
	}
	var resp CtlResponse
	if err := json.Unmarshal(bytes.TrimSpace(line), &resp); err != nil {
		return "", err
	}
	if !resp.OK {
		return "", errors.New(resp.Error)
	}
	return resp.Output, nil
}
