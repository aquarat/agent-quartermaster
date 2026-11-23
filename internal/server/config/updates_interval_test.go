package config

import (
	"testing"
	"time"
)

func TestUpdatesCheckInterval(t *testing.T) {
	for in, want := range map[int]time.Duration{0: 5 * time.Minute, -3: 5 * time.Minute, 1: time.Minute, 15: 15 * time.Minute, 5000: 1440 * time.Minute} {
		if got := (Updates{CheckMinutes: in}).CheckInterval(); got != want {
			t.Errorf("check_minutes=%d: got %v, want %v", in, got, want)
		}
	}
}
