package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/sysio"
)

type MihomoControllerConfig struct {
	ExternalController string `json:"external-controller"`
	Secret             string `json:"secret"`
}

// ReadMihomoControllerConfig parses /data/adb/sandbox_proxy/config.json safely and validates
// that external-controller resolves strictly to loopback so secrets never leave localhost.
func ReadMihomoControllerConfig(configPath string) (baseURL string, secret string, err error) {
	if configPath == "" {
		configPath = contracts.MainConfigPath
	}
	raw, err := sysio.ReadRootOwnedSmallFilePerm(configPath, 4<<20, 0022)
	if err != nil {
		return "", "", err
	}
	var cfg MihomoControllerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		yamlCfg, ok := parseMihomoYAMLFields(raw)
		if !ok {
			return "", "", err
		}
		cfg = yamlCfg
	}
	addr := strings.TrimSpace(cfg.ExternalController)
	if strings.HasPrefix(strings.ToLower(addr), "http://") {
		addr = addr[7:]
	}
	addr = strings.TrimRight(addr, "/")
	if addr == "" {
		return "", "", errors.New("external-controller not configured")
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("invalid external-controller %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		if ip.To4() != nil {
			host = "127.0.0.1"
		} else {
			host = "::1"
		}
	}
	if !isLoopbackHost(host) {
		return "", "", fmt.Errorf("refusing non-loopback external-controller host %q", host)
	}
	return "http://" + net.JoinHostPort(host, port), cfg.Secret, nil
}

func parseMihomoYAMLFields(raw []byte) (MihomoControllerConfig, bool) {
	var cfg MihomoControllerConfig
	found := false
	for _, row := range strings.Split(string(raw), "\n") {
		if len(row) == 0 || row[0] == ' ' || row[0] == '\t' || row[0] == '#' {
			continue
		}
		key, val, ok := strings.Cut(row, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = stripYAMLCommentAndQuotes(strings.TrimSpace(val))
		switch key {
		case "external-controller":
			cfg.ExternalController = val
			found = true
		case "secret":
			cfg.Secret = val
			found = true
		}
	}
	return cfg, found
}

func stripYAMLCommentAndQuotes(s string) string {
	if s == "" {
		return ""
	}
	if q := s[0]; q == '"' || q == '\'' {
		for i := 1; i < len(s); i++ {
			if s[i] == q {
				return s[1:i]
			}
		}
		return strings.Trim(s, `"'`)
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			s = strings.TrimSpace(s[:i])
			break
		}
	}
	return strings.TrimSpace(s)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type mihomoConnsResp struct {
	Connections []struct {
		ID       string `json:"id"`
		Metadata struct {
			InboundName string `json:"inboundName"`
		} `json:"metadata"`
	} `json:"connections"`
}

// FlushSandboxConnections closes ONLY connections whose metadata.inboundName equals inboundName
// (e.g. "sandbox-tproxy") via mihomo's loopback REST API, leaving host/User 0 traffic untouched.
func FlushSandboxConnections(ctx context.Context, configPath, inboundName string) (int, error) {
	if inboundName == "" {
		inboundName = contracts.DefaultSandboxInName
	}
	baseURL, secret, err := ReadMihomoControllerConfig(configPath)
	if err != nil {
		return 0, err
	}
	return flushMihomoInboundURL(ctx, baseURL, secret, inboundName)
}

const maxMihomoRespBytes = 2 << 20

func escapePathSegment(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		isUnreserved := (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~'
		if isUnreserved {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0F])
	}
	return b.String()
}

func loopbackHTTPRequest(ctx context.Context, method, baseURL, reqPath, secret string) (int, []byte, error) {
	if strings.ContainsAny(reqPath, "\r\n") || strings.ContainsAny(secret, "\r\n") {
		return 0, nil, errors.New("invalid CR/LF in loopback HTTP request")
	}
	if !strings.HasPrefix(baseURL, "http://") {
		return 0, nil, fmt.Errorf("unsupported controller scheme in %q", baseURL)
	}
	hostport := strings.TrimRight(strings.TrimPrefix(baseURL, "http://"), "/")
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || !isLoopbackHost(host) {
		return 0, nil, fmt.Errorf("refusing non-loopback controller target %q", baseURL)
	}

	deadline := time.Now().Add(1500 * time.Millisecond)
	if cd, ok := ctx.Deadline(); ok && cd.Before(deadline) {
		deadline = cd
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)

	var reqBuf bytes.Buffer
	reqBuf.Grow(128 + len(reqPath) + len(secret))
	reqBuf.WriteString(method)
	reqBuf.WriteByte(' ')
	reqBuf.WriteString(reqPath)
	reqBuf.WriteString(" HTTP/1.1\r\nHost: ")
	reqBuf.WriteString(hostport)
	reqBuf.WriteString("\r\nConnection: close\r\n")
	if secret != "" {
		reqBuf.WriteString("Authorization: Bearer ")
		reqBuf.WriteString(secret)
		reqBuf.WriteString("\r\n")
	}
	reqBuf.WriteString("\r\n")

	if _, err := conn.Write(reqBuf.Bytes()); err != nil {
		return 0, nil, err
	}

	br := bufio.NewReaderSize(conn, 4096)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return 0, nil, err
	}
	statusFields := strings.Fields(statusLine)
	if len(statusFields) < 2 || !strings.HasPrefix(statusFields[0], "HTTP/1.") {
		return 0, nil, fmt.Errorf("malformed HTTP status line %q", strings.TrimSpace(statusLine))
	}
	code, err := strconv.Atoi(statusFields[1])
	if err != nil {
		return 0, nil, fmt.Errorf("invalid HTTP status code %q", statusFields[1])
	}

	chunked := false
	contentLen := int64(-1)
	for hdrCount := 0; hdrCount < 128; hdrCount++ {
		line, err := br.ReadString('\n')
		if err != nil {
			return 0, nil, err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		k, v, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(v), "chunked") {
				chunked = true
			}
		case "content-length":
			if n, perr := strconv.ParseInt(strings.TrimSpace(v), 10, 64); perr == nil && n >= 0 {
				contentLen = n
			}
		}
	}

	if code == 204 || code == 304 || method == "HEAD" {
		return code, nil, nil
	}
	if chunked {
		body, err := readChunkedBody(br, maxMihomoRespBytes)
		return code, body, err
	}
	if contentLen == 0 {
		return code, nil, nil
	}
	if contentLen > 0 {
		if contentLen > maxMihomoRespBytes {
			return 0, nil, fmt.Errorf("response body %d exceeds limit", contentLen)
		}
		body := make([]byte, contentLen)
		if _, err := io.ReadFull(br, body); err != nil {
			return 0, nil, err
		}
		return code, body, nil
	}
	body, err := io.ReadAll(io.LimitReader(br, maxMihomoRespBytes+1))
	if err != nil {
		return 0, nil, err
	}
	if len(body) > maxMihomoRespBytes {
		return 0, nil, errors.New("response body exceeds limit")
	}
	return code, body, nil
}

func readChunkedBody(br *bufio.Reader, limit int) ([]byte, error) {
	var out bytes.Buffer
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		sizePart, _, _ := strings.Cut(strings.TrimSpace(line), ";")
		sz, err := strconv.ParseInt(strings.TrimSpace(sizePart), 16, 64)
		if err != nil || sz < 0 {
			return nil, fmt.Errorf("invalid chunk size %q", line)
		}
		if sz == 0 {
			return out.Bytes(), nil
		}
		if sz > int64(limit-out.Len()) {
			return nil, errors.New("chunked response exceeds limit")
		}
		if _, err := io.CopyN(&out, br, sz); err != nil {
			return nil, err
		}
		crlf, err := br.ReadString('\n')
		if err != nil || strings.TrimRight(crlf, "\r\n") != "" {
			return nil, errors.New("malformed chunk terminator")
		}
	}
}

func flushMihomoInboundURL(ctx context.Context, baseURL, secret, inboundName string) (int, error) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	status, body, err := loopbackHTTPRequest(cctx, "GET", baseURL, "/connections", secret)
	if err != nil {
		return 0, err
	}
	if status != 200 {
		return 0, fmt.Errorf("GET /connections status %d", status)
	}

	var list mihomoConnsResp
	if err := json.Unmarshal(body, &list); err != nil {
		return 0, err
	}

	var targetIDs []string
	for _, c := range list.Connections {
		if c.Metadata.InboundName != inboundName {
			continue
		}
		if c.ID == "" || c.ID == "." || c.ID == ".." || strings.ContainsAny(c.ID, "/?\\#%\r\n") {
			continue
		}
		targetIDs = append(targetIDs, c.ID)
	}
	if len(targetIDs) == 0 {
		return 0, nil
	}

	workers := 8
	if len(targetIDs) < workers {
		workers = len(targetIDs)
	}
	jobs := make(chan string, len(targetIDs))
	for _, id := range targetIDs {
		jobs <- id
	}
	close(jobs)

	var closed atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for id := range jobs {
				if cctx.Err() != nil {
					return
				}
				delStatus, _, derr := loopbackHTTPRequest(cctx, "DELETE", baseURL, "/connections/"+escapePathSegment(id), secret)
				if derr == nil && delStatus >= 200 && delStatus < 300 {
					closed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	return int(closed.Load()), nil
}
