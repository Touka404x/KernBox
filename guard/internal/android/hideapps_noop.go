//go:build !oem_hyperos

package android

import (
	"context"
	"fmt"

	"sandbox_guard/internal/oem"
)

// SyncHideApps is a compile-time no-op on OEM profiles without HyperOS/MIUI launcher hiding.
func SyncHideApps(_ context.Context, _ Runner, userID, serial int) (HideSyncResult, error) {
	if oem.IsForbiddenUser(userID) || serial <= 0 {
		return HideSyncResult{}, fmt.Errorf("invalid work user %d / serial %d", userID, serial)
	}
	return HideSyncResult{
		UserID:  userID,
		Serial:  serial,
		Skipped: true,
	}, nil
}
