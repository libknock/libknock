//go:build !linux && !windows && !darwin

package knock

import "errors"

func CheckClientSupport(method string) error {
	if method != "tcp-syn" && method != TCP_SYNSeqMethod {
		return nil
	}
	return errors.New("tcp-syn knock is not implemented on this platform; switch knock.method to udp")
}
func CheckServerPrivileges() error {
	return errors.New("server requires Linux CAP_NET_ADMIN/CAP_NET_RAW, macOS BPF permissions, or must be run as root")
}
