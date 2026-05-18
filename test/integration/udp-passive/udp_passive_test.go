package udp_passive_test

import (
	"os"
	"testing"
)

func TestRealUDPPassiveValidationOptIn(t *testing.T) {
	if os.Getenv("LIBKNOCK_REAL_FIREWALL_TESTS") != "1" {
		t.Skip("set LIBKNOCK_REAL_FIREWALL_TESTS=1 to run real firewall tests")
	}
}
