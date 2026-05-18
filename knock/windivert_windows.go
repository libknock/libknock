//go:build windows

package knock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	windivertLayerNetwork = 0
	windivertFlagSendOnly = 0x00000800
	windivertAddrOutbound = 1 << 17
)

type windivertAddress struct {
	Timestamp int64
	Flags     uint32
	Reserved  uint32
	Data      [8]uint64
}

var (
	windivertDLL                     = syscall.NewLazyDLL("WinDivert.dll")
	procWinDivertOpen                = windivertDLL.NewProc("WinDivertOpen")
	procWinDivertSend                = windivertDLL.NewProc("WinDivertSend")
	procWinDivertClose               = windivertDLL.NewProc("WinDivertClose")
	procWinDivertHelperCalcChecksums = windivertDLL.NewProc("WinDivertHelperCalcChecksums")
)

func init() {
	initWinDivertDLLSearchPath()
}

func initWinDivertDLLSearchPath() {
	for _, dir := range []string{filepath.Dir(os.Args[0]), filepath.Join(filepath.Dir(os.Args[0]), "WinDivert"), filepath.Join(filepath.Dir(os.Args[0]), "windivert")} {
		if dir == "." || dir == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "WinDivert.dll")); err != nil {
			continue
		}
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		addDLLDirectory := kernel32.NewProc("AddDllDirectory")
		setDefaultDLLDirectories := kernel32.NewProc("SetDefaultDllDirectories")
		path, err := syscall.UTF16PtrFromString(dir)
		if err == nil {
			_, _, _ = setDefaultDLLDirectories.Call(0x00001000 | 0x00000400 | 0x00000800)
			_, _, _ = addDLLDirectory.Call(uintptr(unsafe.Pointer(path)))
		}
		return
	}
}

func windowsSendIPPacketWinDivert(packet []byte) error {
	if len(packet) == 0 {
		return fmt.Errorf("empty IPv4 packet")
	}
	if err := windivertDLL.Load(); err != nil {
		return fmt.Errorf("WinDivert.dll not found: %w; place WinDivert.dll next to knock-proxy.exe or install WinDivert, then run as administrator", err)
	}
	filter, err := syscall.BytePtrFromString("false")
	if err != nil {
		return err
	}
	handle, _, callErr := procWinDivertOpen.Call(uintptr(unsafe.Pointer(filter)), uintptr(windivertLayerNetwork), 0, uintptr(windivertFlagSendOnly))
	if handle == ^uintptr(0) || handle == 0 {
		return fmt.Errorf("WinDivertOpen failed: %w; run as administrator and ensure the WinDivert driver files are available", callErr)
	}
	defer procWinDivertClose.Call(handle)

	addr := windivertAddress{Flags: windivertLayerNetwork | windivertAddrOutbound}
	if procWinDivertHelperCalcChecksums.Find() == nil {
		_, _, _ = procWinDivertHelperCalcChecksums.Call(uintptr(unsafe.Pointer(&packet[0])), uintptr(uint32(len(packet))), uintptr(unsafe.Pointer(&addr)), 0)
	}
	var sent uint32
	ok, _, sendErr := procWinDivertSend.Call(handle, uintptr(unsafe.Pointer(&packet[0])), uintptr(uint32(len(packet))), uintptr(unsafe.Pointer(&sent)), uintptr(unsafe.Pointer(&addr)))
	runtime.KeepAlive(packet)
	if ok == 0 {
		return fmt.Errorf("WinDivertSend failed: %w", sendErr)
	}
	if sent != uint32(len(packet)) {
		return fmt.Errorf("WinDivertSend sent %d bytes, want %d", sent, len(packet))
	}
	return nil
}

func windowsHasWinDivert() bool {
	return windivertDLL.Load() == nil
}

func windowsIsDLLNotFound(err error) bool {
	return errors.Is(err, syscall.ERROR_MOD_NOT_FOUND) || errors.Is(err, syscall.ERROR_PROC_NOT_FOUND)
}
