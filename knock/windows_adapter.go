//go:build windows

package knock

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func windowsNpcapAdapterNameForInterface(iface *net.Interface) (string, error) {
	addrs, err := windowsAdapterAddresses()
	if err != nil {
		return "", err
	}
	var macMatch string
	for _, addr := range addrs {
		if int(addr.ifIndex) == iface.Index && addr.adapterName != "" {
			return npcapDeviceName(addr.adapterName), nil
		}
		if iface.HardwareAddr != nil && addr.hardwareAddr != nil && iface.HardwareAddr.String() == addr.hardwareAddr.String() {
			macMatch = addr.adapterName
		}
	}
	if macMatch != "" {
		return npcapDeviceName(macMatch), nil
	}
	return "", fmt.Errorf("no IP Helper adapter address matched interface %q index %d", iface.Name, iface.Index)
}

func npcapDeviceName(adapterName string) string {
	adapterName = strings.TrimSpace(adapterName)
	upper := strings.ToUpper(adapterName)
	if strings.HasPrefix(upper, `\DEVICE\NPF_`) || strings.HasPrefix(upper, `\\DEVICE\\NPF_`) {
		return adapterName
	}
	return `\Device\NPF_` + adapterName
}

type windowsAdapterAddress struct {
	ifIndex      uint32
	adapterName  string
	hardwareAddr net.HardwareAddr
}

func windowsAdapterAddresses() ([]windowsAdapterAddress, error) {
	size := uint32(15 * 1024)
	flags := uint32(windows.GAA_FLAG_INCLUDE_ALL_INTERFACES | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER)
	for attempts := 0; attempts < 3; attempts++ {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET, flags, 0, first, &size)
		if err == nil {
			var out []windowsAdapterAddress
			for aa := first; aa != nil; aa = aa.Next {
				name := windows.BytePtrToString(aa.AdapterName)
				if name == "" {
					continue
				}
				var mac net.HardwareAddr
				if aa.PhysicalAddressLength > 0 && aa.PhysicalAddressLength <= uint32(len(aa.PhysicalAddress)) {
					mac = append(net.HardwareAddr(nil), aa.PhysicalAddress[:aa.PhysicalAddressLength]...)
				}
				out = append(out, windowsAdapterAddress{ifIndex: aa.IfIndex, adapterName: name, hardwareAddr: mac})
			}
			return out, nil
		}
		if errno, ok := err.(syscall.Errno); ok && errno == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		return nil, fmt.Errorf("GetAdaptersAddresses failed: %w", err)
	}
	return nil, fmt.Errorf("GetAdaptersAddresses failed after buffer resize")
}
