package store

import (
	"encoding/json"
	"time"
)

// ─────────────────────────────────────────────
// Time / JSON helpers
// ─────────────────────────────────────────────

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339Nano)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, _ = time.Parse(time.RFC3339, s)
	}
	return t
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func i2b(i int) bool { return i != 0 }

func toJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func fromJSON[T any](s string) T {
	var v T
	json.Unmarshal([]byte(s), &v)
	return v
}

func fromJSONPtr[T any](s string) *T {
	if s == "" {
		return nil
	}
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil
	}
	return &v
}
