package relay

import (
	"errors"

	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/knock"
)

func validateRelayFirewallMode(fw firewall.Backend, method string) error {
	if fw == nil || fw.Name() == "noop" {
		return nil
	}
	if method == "" {
		return errors.New("relay firewall backend requires a knock method; auth-only relay must use firewall backend noop")
	}
	return knock.ValidateRelayServerMethod(method)
}
