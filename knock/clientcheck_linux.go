//go:build linux

package knock

import (
	"errors"
	"os"
)

func CheckClientSupport(method string) error {
	if method != "tcp-syn" && method != TCP_SYNSeqMethod {
		return nil
	}
	if os.Geteuid() == 0 || hasEffectiveCaps(13) {
		return nil
	}
	return errors.New("tcp-syn/tcp-syn-seq knock requires CAP_NET_RAW or root; remediation: run as root, setcap cap_net_raw+ep on binary, or use systemd AmbientCapabilities=CAP_NET_RAW; switch knock.method to udp if raw packet injection is unavailable")
}
