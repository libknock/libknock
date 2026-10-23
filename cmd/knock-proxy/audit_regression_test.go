package main

import (
	"testing"
	"time"
)

func TestAuthReplayTTLCoversTimeWindow(t *testing.T) {
	if got := authReplayTTL(10*time.Second, 30*time.Second); got <= time.Minute {
		t.Fatalf("authReplayTTL raised to %v, must exceed 2*window", got)
	}
	if got := authReplayTTL(300*time.Second, 30*time.Second); got != 300*time.Second {
		t.Fatalf("authReplayTTL changed a safe value to %v", got)
	}
}
