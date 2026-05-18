//go:build darwin

package knock

import (
	"errors"
	"os"
)

func CheckClientSupport(method string) error {
	if method != TCPSYNMethod && method != TCP_SYNSeqMethod {
		return nil
	}
	if os.Geteuid() == 0 {
		return nil
	}
	return errors.New("tcp-syn/tcp-syn-seq knock on macOS requires root/raw socket permission; run as root or switch knock.method to udp/udp-seq")
}
