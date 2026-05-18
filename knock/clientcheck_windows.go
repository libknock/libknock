//go:build windows

package knock

import "fmt"

func CheckClientSupport(method string) error {
	if method != "tcp-syn" && method != "tcp-syn-seq" {
		return nil
	}
	if windowsHasWinDivert() {
		return nil
	}
	if err := packetDLL.Load(); err != nil {
		return fmt.Errorf("tcp-syn/tcp-syn-seq knock on Windows requires WinDivert.dll or Npcap Packet.dll. Place WinDivert.dll next to knock-proxy.exe, install Npcap, or switch knock.method to udp/udp-seq: %w", err)
	}
	return nil
}
