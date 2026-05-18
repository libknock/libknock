//go:build windows

package knock

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var (
	packetDLL              = syscall.NewLazyDLL("Packet.dll")
	procPacketOpenAdapter  = packetDLL.NewProc("PacketOpenAdapter")
	procPacketCloseAdapter = packetDLL.NewProc("PacketCloseAdapter")
	procPacketAllocate     = packetDLL.NewProc("PacketAllocatePacket")
	procPacketInit         = packetDLL.NewProc("PacketInitPacket")
	procPacketSend         = packetDLL.NewProc("PacketSendPacket")
	procPacketFree         = packetDLL.NewProc("PacketFreePacket")
	procPacketGetNames     = packetDLL.NewProc("PacketGetAdapterNames")
)

func init() {
	initNpcapDLLSearchPath()
}

func initNpcapDLLSearchPath() {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	npcapDir := filepath.Join(systemRoot, "System32", "Npcap")
	if st, err := os.Stat(npcapDir); err != nil || !st.IsDir() {
		return
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setDLLDirectory := kernel32.NewProc("SetDllDirectoryW")
	path, err := syscall.UTF16PtrFromString(npcapDir)
	if err != nil {
		return
	}
	_, _, _ = setDLLDirectory.Call(uintptr(unsafe.Pointer(path)))
}

func windowsSendFrame(adapterNames []string, frame []byte) error {
	if len(frame) == 0 {
		return fmt.Errorf("empty Ethernet frame")
	}
	if err := packetDLL.Load(); err != nil {
		return fmt.Errorf("Npcap Packet.dll not found: %w; install Npcap, or reinstall with WinPcap API-compatible mode if your version does not expose %s", err, filepath.Join(os.Getenv("SystemRoot"), "System32", "Npcap", "Packet.dll"))
	}
	var last error
	var tried []string
	for _, name := range adapterNames {
		if name == "" {
			continue
		}
		tried = append(tried, name)
		if err := packetSendFrame(name, frame); err != nil {
			last = err
			continue
		}
		return nil
	}
	if last != nil {
		return fmt.Errorf("%w; tried adapters: %s", last, strings.Join(tried, ", "))
	}
	return fmt.Errorf("no Npcap adapter candidate found")
}

func packetSendFrame(adapterName string, frame []byte) error {
	name, err := syscall.BytePtrFromString(adapterName)
	if err != nil {
		return err
	}
	adapter, _, err := procPacketOpenAdapter.Call(uintptr(unsafe.Pointer(name)))
	if adapter == 0 {
		return fmt.Errorf("PacketOpenAdapter(%s) failed: %w", adapterName, err)
	}
	defer procPacketCloseAdapter.Call(adapter)

	pkt, _, err := procPacketAllocate.Call()
	if pkt == 0 {
		return fmt.Errorf("PacketAllocatePacket failed: %w", err)
	}
	defer procPacketFree.Call(pkt)

	procPacketInit.Call(pkt, uintptr(unsafe.Pointer(&frame[0])), uintptr(uint32(len(frame))))
	ok, _, err := procPacketSend.Call(adapter, pkt, uintptr(1))
	runtime.KeepAlive(frame)
	if ok == 0 {
		return fmt.Errorf("PacketSendPacket(%s) failed: %w", adapterName, err)
	}
	return nil
}

func windowsNpcapAdapterNames() []string {
	if err := packetDLL.Load(); err != nil {
		return nil
	}
	var size uint32
	procPacketGetNames.Call(0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		size = 64 * 1024
	}
	buf := make([]byte, size)
	ok, _, _ := procPacketGetNames.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 || size == 0 {
		return nil
	}
	if int(size) < len(buf) {
		buf = buf[:size]
	}
	parts := bytes.Split(buf, []byte{0})
	out := make([]string, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		s := strings.TrimSpace(string(p))
		if s == "" || !strings.Contains(strings.ToUpper(s), "NPF") || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
