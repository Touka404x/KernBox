//go:build oem_hyperos

package android

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"sandbox_guard/internal/contracts"
	"sandbox_guard/internal/oem"
)

// HideAppBean matches MIUI/HyperOS Home com.miui.home.launcher.hideapp.HideAppBean JSON.
type HideAppBean struct {
	ActivityName string `json:"activityName"`
	MHashCode    int32  `json:"mHashCode"`
	PackageName  string `json:"packageName"`
	SerialNumber string `json:"serialNumber"`
}

type LauncherActivity struct {
	PackageName  string
	ActivityName string
}

func isResolveWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func extractResolveComponent(line string) (string, string, bool) {
	for i := 0; i < len(line); i++ {
		if line[i] != '/' {
			continue
		}
		start := i
		for start > 0 {
			c := line[start-1]
			if isResolveWordByte(c) || c == '.' {
				start--
				continue
			}
			break
		}
		if start == i || (start > 0 && isResolveWordByte(line[start-1])) {
			continue
		}
		pkg := line[start:i]
		if !contracts.PackageNameRegex.MatchString(pkg) {
			continue
		}
		end := i + 1
		for end < len(line) {
			c := line[end]
			if isResolveWordByte(c) || c == '.' || c == '$' {
				end++
				continue
			}
			break
		}
		for end > i+1 && !isResolveWordByte(line[end-1]) {
			end--
		}
		if end <= i+1 {
			continue
		}
		return pkg, line[i+1 : end], true
	}
	return "", "", false
}

// JavaStringHash replicates java.lang.String.hashCode() over UTF-16 code units.
func JavaStringHash(s string) int32 {
	var h int32
	for _, u := range utf16.Encode([]rune(s)) {
		h = 31*h + int32(u)
	}
	return h
}

// JavaObjectsHash replicates java.util.Objects.hash(Object...).
func JavaObjectsHash(parts ...string) int32 {
	h := int32(1)
	for _, p := range parts {
		h = 31*h + JavaStringHash(p)
	}
	return h
}

// BuildHideAppBean constructs one MIUI/HyperOS HideAppBean JSON object.
func BuildHideAppBean(pkg, activity, serial string) HideAppBean {
	return HideAppBean{
		ActivityName: activity,
		MHashCode:    JavaObjectsHash(pkg, activity, serial),
		PackageName:  pkg,
		SerialNumber: serial,
	}
}

// ParseQueryActivities parses `cmd package query-activities --user <u> -a android.intent.action.MAIN -c android.intent.category.LAUNCHER`.
func ParseQueryActivities(output string) []LauncherActivity {
	seen := make(map[string]LauncherActivity)
	var inActivityInfo, inAppInfo bool
	var curPkg, curName string

	flush := func() {
		if curPkg != "" && curName != "" {
			if strings.HasPrefix(curName, ".") {
				curName = curPkg + curName
			}
			if contracts.ValidPackageName(curPkg) {
				key := curPkg + "/" + curName
				seen[key] = LauncherActivity{PackageName: curPkg, ActivityName: curName}
			}
		}
		curPkg, curName = "", ""
	}

	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "Activity #") || line == "" {
			flush()
			inActivityInfo = false
			inAppInfo = false
			continue
		}
		if line == "ActivityInfo:" {
			inActivityInfo = true
			inAppInfo = false
			continue
		}
		if line == "ApplicationInfo:" {
			inActivityInfo = false
			inAppInfo = true
			continue
		}
		if inAppInfo {
			continue
		}
		if inActivityInfo {
			if strings.HasPrefix(line, "name=") {
				curName = strings.TrimSpace(strings.TrimPrefix(line, "name="))
			} else if strings.HasPrefix(line, "packageName=") {
				curPkg = strings.TrimSpace(strings.TrimPrefix(line, "packageName="))
			}
			continue
		}
		if pkg, act, ok := extractResolveComponent(line); ok {
			if strings.HasPrefix(act, ".") {
				act = pkg + act
			}
			if contracts.ValidPackageName(pkg) {
				seen[pkg+"/"+act] = LauncherActivity{PackageName: pkg, ActivityName: act}
			}
		}
	}
	flush()

	out := make([]LauncherActivity, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PackageName != out[j].PackageName {
			return out[i].PackageName < out[j].PackageName
		}
		return out[i].ActivityName < out[j].ActivityName
	})
	return out
}

// MergeHideAppList preserves all non-work-serial entries (e.g. User 0 serialNumber="0")
// and merges the exact set of work launcher activities for workSerial.
func MergeHideAppList(existing []HideAppBean, workActivities []LauncherActivity, workSerial string) (merged []HideAppBean, missing []LauncherActivity, staleCount int) {
	existingWork := make(map[string]HideAppBean)
	for _, entry := range existing {
		if entry.SerialNumber == workSerial {
			existingWork[entry.PackageName+"/"+entry.ActivityName] = entry
		} else {
			merged = append(merged, entry)
		}
	}

	desiredKeys := make(map[string]struct{}, len(workActivities))
	for _, act := range workActivities {
		key := act.PackageName + "/" + act.ActivityName
		desiredKeys[key] = struct{}{}
		if prev, ok := existingWork[key]; ok {
			merged = append(merged, prev)
		} else {
			missing = append(missing, act)
			merged = append(merged, BuildHideAppBean(act.PackageName, act.ActivityName, workSerial))
		}
	}
	for key := range existingWork {
		if _, ok := desiredKeys[key]; !ok {
			staleCount++
		}
	}
	return merged, missing, staleCount
}

func ParseHideAppListJSON(raw string) ([]HideAppBean, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var beans []HideAppBean
	if err := json.Unmarshal([]byte(trimmed), &beans); err != nil {
		return nil, err
	}
	return beans, nil
}

// SyncHideApps queries User <u> launcher activities and updates HyperOS/MIUI Home HideAppProvider +
// Settings.Secure.miui_home_hide_app_list while preserving User 0 entries.
func SyncHideApps(ctx context.Context, r Runner, userID, serial int) (HideSyncResult, error) {
	if oem.IsForbiddenUser(userID) || serial <= 0 {
		return HideSyncResult{}, fmt.Errorf("invalid work user %d / serial %d", userID, serial)
	}
	prof := oem.Current()
	secureKey := prof.HideSecureListKey
	if secureKey == "" {
		secureKey = "miui_home_hide_app_list"
	}
	providerURI := prof.HideProviderURI
	if providerURI == "" {
		providerURI = "content://com.miui.home.app.hide"
	}

	u := strconv.Itoa(userID)
	serialStr := strconv.Itoa(serial)

	actOut, err := r.Run(ctx, 8*time.Second, "", "cmd", "package", "query-activities",
		"--user", u, "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER")
	if err != nil {
		return HideSyncResult{}, fmt.Errorf("query-activities: %w", err)
	}
	workActs := ParseQueryActivities(actOut)

	existingRaw, getErr := r.Run(ctx, 4*time.Second, "", "settings", "--user", "0", "get", "secure", secureKey)
	if getErr != nil {
		return HideSyncResult{}, fmt.Errorf("read secure %s: %w", secureKey, getErr)
	}
	existing, parseErr := ParseHideAppListJSON(existingRaw)
	if parseErr != nil {
		return HideSyncResult{}, fmt.Errorf("parse secure %s (refusing to overwrite): %w", secureKey, parseErr)
	}

	merged, missing, stale := MergeHideAppList(existing, workActs, serialStr)
	res := HideSyncResult{
		UserID:      userID,
		Serial:      serial,
		WorkCount:   len(workActs),
		TotalHidden: len(merged),
	}
	if len(missing) == 0 && stale == 0 {
		return res, nil
	}

	// Prefer HideAppProvider live insert so com.miui.home receives ACTION_PACKAGE_CHANGED without kill.
	var warnMsgs []string
	for _, act := range missing {
		_, cerr := r.Run(ctx, 4*time.Second, "", "content", "insert", "--user", "0",
			"--uri", providerURI,
			"--bind", "packageName:s:"+act.PackageName,
			"--bind", "activityName:s:"+act.ActivityName,
			"--bind", "serialNumber:s:"+serialStr)
		if cerr != nil {
			warnMsgs = append(warnMsgs, cerr.Error())
		} else {
			res.Inserted++
		}
	}

	// Re-read Settings.Secure and ensure exact merged JSON if stale entries exist or insert missed anything.
	afterRaw, _ := r.Run(ctx, 4*time.Second, "", "settings", "--user", "0", "get", "secure", secureKey)
	afterBeans, afterErr := ParseHideAppListJSON(afterRaw)
	needPut := stale > 0 || afterErr != nil
	if !needPut {
		_, stillMissing, stillStale := MergeHideAppList(afterBeans, workActs, serialStr)
		if len(stillMissing) > 0 || stillStale > 0 {
			needPut = true
		}
	}
	if needPut {
		payload, err := json.Marshal(merged)
		if err != nil {
			return res, err
		}
		if _, err := r.Run(ctx, 4*time.Second, "", "settings", "--user", "0", "put", "secure", secureKey, string(payload)); err != nil {
			return res, fmt.Errorf("settings put %s: %w", secureKey, err)
		}
		res.UpdatedStore = true
	}
	if len(warnMsgs) > 0 {
		res.Warning = strings.Join(warnMsgs[:min(len(warnMsgs), 3)], "; ")
	}
	return res, nil
}
