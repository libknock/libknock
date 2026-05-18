package platform_test

import (
	"os"
	"testing"
)

func TestRealPlatformValidationOptIn(t *testing.T) {
	if os.Getenv("LIBKNOCK_REAL_FIREWALL_TESTS") != "1" {
		t.Skip("set LIBKNOCK_REAL_FIREWALL_TESTS=1 to run real firewall tests")
	}
}
