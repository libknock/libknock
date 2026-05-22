package firewall

import (
	"errors"
	"testing"
)

func TestIsMissingFirewallObjectSamples(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"iptables missing rule", errors.New("iptables: Bad rule (does a matching rule exist in that chain?)"), true},
		{"nft missing table", errors.New("Error: No such table: inet knock_gateway"), true},
		{"ipset not in set", errors.New("ipset v7.19: The element is not in the set"), true},
		{"ipset already absent", errors.New("it's not added"), true},
		{"command missing", errors.New("exec: \"iptables\": executable file not found in $PATH: no such file or directory"), true},
		{"missing extension is not object absence", errors.New("iptables: No chain/target/match by that name."), false},
		{"permission denied", errors.New("iptables: Permission denied (you must be root)"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isMissingFirewallObject(tt.err); got != tt.want {
				t.Fatalf("isMissingFirewallObject(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
