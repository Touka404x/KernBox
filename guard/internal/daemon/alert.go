package daemon

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

const alertCooldown = 5 * time.Minute

func sanitizeAlertText(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	var b strings.Builder
	b.Grow(len(s))
	lastSpace := false
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if r == ' ' {
			if lastSpace {
				continue
			}
			lastSpace = true
		} else {
			lastSpace = false
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if maxLen > 0 {
		runes := []rune(out)
		if len(runes) > maxLen {
			out = strings.TrimSpace(string(runes[:maxLen-1])) + "…"
		}
	}
	return out
}

// FormatAlertArgs builds sanitized argv for `cmd notification post -S bigtext -t <title> <tag> <body>`.
func FormatAlertArgs(tag, title, body string) []string {
	t := sanitizeAlertText(title, 64)
	if t == "" {
		t = "KernBox Alert"
	}
	tg := sanitizeAlertText(tag, 48)
	if tg == "" {
		tg = "kernbox_alert"
	}
	bd := sanitizeAlertText(body, 240)
	if bd == "" {
		bd = t
	}
	return []string{"notification", "post", "-S", "bigtext", "-t", t, tg, bd}
}

// postSystemAlert sends an Android system notification via `cmd notification post` with deduplication cooldown.
func (d *Daemon) postSystemAlert(ctx context.Context, key, tag, title, body string) bool {
	if d == nil || d.runner == nil || ctx.Err() != nil {
		return false
	}
	cleanBody := sanitizeAlertText(body, 240)
	if cleanBody == "" {
		return false
	}
	dedupKey := key + "|" + cleanBody
	now := time.Now()
	d.alertMu.Lock()
	if d.alertLastSent == nil {
		d.alertLastSent = make(map[string]time.Time, 4)
	}
	if prev, ok := d.alertLastSent[dedupKey]; ok && now.Sub(prev) < alertCooldown {
		d.alertMu.Unlock()
		return false
	}
	d.alertLastSent[dedupKey] = now
	d.alertMu.Unlock()

	_, err := d.runner.Run(ctx, 3*time.Second, "", "cmd", FormatAlertArgs(tag, title, cleanBody)...)
	if err != nil {
		if d.log != nil {
			d.log.Printf("postSystemAlert (%s): %v", tag, err)
		}
		return false
	}
	return true
}

func (d *Daemon) notifyAlertAsync(key, tag, title, body string) {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.shuttingDown {
		d.mu.Unlock()
		return
	}
	bg := d.superviseCtx
	if bg == nil {
		bg = context.Background()
	}
	d.maintWg.Add(1)
	d.mu.Unlock()
	go func() {
		defer d.maintWg.Done()
		cctx, cancel := context.WithTimeout(bg, 4*time.Second)
		defer cancel()
		_ = d.postSystemAlert(cctx, key, tag, title, body)
	}()
}

func (d *Daemon) hasPersistentBootIssueLocked() bool {
	_, _, disabledFlag := d.resolvedStealthPaths()
	if _, err := os.Stat(disabledFlag); err == nil {
		return true
	}
	if !d.policyLoaded {
		return true
	}
	if !hasValidBrokerAuthUID(d.resolvedBrokerAuthPath()) {
		return true
	}
	return false
}

// checkBootHealthAndAlert inspects post-boot daemon health, sets d.bootAlert, and emits a visible
// system notification if startup landed in an abnormal state (so failures never silently stall).
func (d *Daemon) checkBootHealthAndAlert(ctx context.Context) {
	if d == nil || ctx.Err() != nil {
		return
	}
	collectIssues := func() []string {
		var issues []string
		_, _, disabledFlag := d.resolvedStealthPaths()
		if _, err := os.Stat(disabledFlag); err == nil {
			issues = append(issues, "Zygisk 隐身模块因启动异常已自动熔断关闭，请打开 KernBox 查看自检")
		}
		d.mu.Lock()
		loaded := d.policyLoaded
		paused := d.paused
		state := d.state
		policy := d.policy
		lastErr := strings.TrimSpace(d.lastError)
		d.mu.Unlock()

		if !loaded {
			issues = append(issues, "policy.json 未加载，沙盒处于闭锁状态，请检查配置文件")
			return issues
		}
		if !hasValidBrokerAuthUID(d.resolvedBrokerAuthPath()) {
			issues = append(issues, "控制端签名校验未通过，KernBox App 无法连接守护进程")
		}
		if !paused {
			tproxyOK := !policy.IsTProxy() || d.tproxyReady(policy)
			if state != StateOpen || !tproxyOK {
				detail := fmt.Sprintf("沙盒未就绪 (%s)", state)
				if policy.IsTProxy() && !tproxyOK {
					detail = fmt.Sprintf("TProxy 代理核心端口 :%d 未就绪 (%s)", policy.TProxyPort, state)
				}
				if lastErr != "" {
					detail += ": " + lastErr
				}
				issues = append(issues, detail)
			}
		}
		return issues
	}

	issues := collectIssues()
	if len(issues) > 0 {
		d.mu.Lock()
		pausedNow := d.paused
		loadedNow := d.policyLoaded
		d.mu.Unlock()
		if loadedNow && !pausedNow {
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			issues = collectIssues()
		}
	}

	summary := strings.Join(issues, "；")
	d.mu.Lock()
	d.bootAlert = summary
	d.mu.Unlock()

	if summary != "" {
		if d.log != nil {
			d.log.Printf("boot health alert: %s", summary)
		}
		_ = d.postSystemAlert(ctx, "boot_health", "kernbox_boot_alert", "KernBox 启动异常", summary)
	}
}
