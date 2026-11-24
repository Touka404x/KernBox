package android

// HideSyncResult summarizes launcher hide-app synchronization (populated on OEMs with
// launcher hide support such as HyperOS/MIUI; Skipped=true elsewhere).
type HideSyncResult struct {
	UserID       int    `json:"user_id"`
	Serial       int    `json:"serial"`
	WorkCount    int    `json:"work_activities"`
	TotalHidden  int    `json:"total_hidden"`
	Inserted     int    `json:"inserted"`
	UpdatedStore bool   `json:"updated_store"`
	Skipped      bool   `json:"skipped,omitempty"`
	Warning      string `json:"warning,omitempty"`
}
