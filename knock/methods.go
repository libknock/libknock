package knock

import "fmt"

var activeUDPMethods = map[string]struct{}{
	UDPMethod:    {},
	UDPSeqMethod: {},
}

var relayServerMethods = map[string]struct{}{
	TCPSYNMethod:     {},
	TCP_SYNSeqMethod: {},
	UDPMethod:        {},
	UDPSeqMethod:     {},
	UDPPassiveMethod: {},
	UDPPassiveSeq:    {},
}

func NormalizeMethod(method string) string {
	switch method {
	case "udp-sequence":
		return UDPSeqMethod
	case "udp-passive-sequence":
		return UDPPassiveSeq
	default:
		return method
	}
}

func IsActiveUDPMethod(method string) bool {
	_, ok := activeUDPMethods[NormalizeMethod(method)]
	return ok
}

func IsRelayServerMethod(method string) bool {
	_, ok := relayServerMethods[NormalizeMethod(method)]
	return ok
}

func ValidateRelayServerMethod(method string) error {
	if IsRelayServerMethod(method) {
		return nil
	}
	return fmt.Errorf("unsupported knock method %q", method)
}
