package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
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

func flushMihomoInboundURL(ctx context.Context, baseURL, secret, inboundName string) (int, error) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	client := &http.Client{
		Timeout:   1500 * time.Millisecond,
		Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, baseURL+"/connections", nil)
	if err != nil {
		return 0, err
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET /connections status %d", resp.StatusCode)
	}

	var list mihomoConnsResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&list); err != nil {
		return 0, err
	}

	closed := 0
	for _, c := range list.Connections {
		if c.Metadata.InboundName != inboundName {
			continue
		}
		if c.ID == "" || c.ID == "." || c.ID == ".." || strings.ContainsAny(c.ID, "/?\\#%") {
			continue
		}
		delReq, derr := http.NewRequestWithContext(cctx, http.MethodDelete, baseURL+"/connections/"+url.PathEscape(c.ID), nil)
		if derr != nil {
			continue
		}
		if secret != "" {
			delReq.Header.Set("Authorization", "Bearer "+secret)
		}
		delResp, derr := client.Do(delReq)
		if derr == nil {
			_ = delResp.Body.Close()
			if delResp.StatusCode >= 200 && delResp.StatusCode < 300 {
				closed++
			}
		}
	}
	return closed, nil
}
