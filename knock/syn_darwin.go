//go:build darwin

package knock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const bpfReadBufferLen = 65535

func Send(ctx context.Context, opts SendOptions) error {
	ctx = backgroundIfNil(ctx)
	if err := ValidateSendOptions(opts); err != nil {
		return err
	}
	if opts.TimeWindow <= 0 {
		opts.TimeWindow = 30 * time.Second
	}
	remote, err := net.ResolveTCPAddr("tcp", opts.ServerAddr)
	if err != nil {
		return err
	}
	if remote.IP == nil {
		return fmt.Errorf("server address %q did not resolve to an IP address", opts.ServerAddr)
	}
	if remote.IP.To4() != nil {
		return darwinSendIPv4(ctx, opts, remote)
	}
	return darwinSendIPv6(ctx, opts, remote)
}

func SendSYNSequence(ctx context.Context, opts SendOptions) error {
	ctx = backgroundIfNil(ctx)
	if err := ValidateSendOptions(opts); err != nil {
		return err
	}
	seq := normalizedSequenceOptions(opts.Sequence)
	remote, err := net.ResolveTCPAddr("tcp", opts.ServerAddr)
	if err != nil {
		return err
	}
	if remote.IP == nil {
		return fmt.Errorf("server address %q did not resolve to an IP address", opts.ServerAddr)
	}
	if remote.IP.To4() != nil {
		return darwinSendSYNSequenceIPv4(ctx, opts, remote, seq)
	}
	return darwinSendSYNSequenceIPv6(ctx, opts, remote, seq)
}

func darwinSendIPv4(ctx context.Context, opts SendOptions, remote *net.TCPAddr) error {
	localIP, err := outboundIPv4(remote)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return darwinRawSocketError("tcp-syn knock", err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return err
	}
	fields := ComputeSYNFields(opts.Secret, opts.ClientID, opts.ServerPort, SlotFor(time.Now(), opts.TimeWindow))
	srcPort, err := randomEphemeralPort()
	if err != nil {
		return err
	}
	packet, err := buildSYNPacket(localIP, remote.IP.To4(), srcPort, opts.ServerPort, fields)
	if err != nil {
		return err
	}
	var dst [4]byte
	copy(dst[:], remote.IP.To4())
	return sendSockaddr(ctx, fd, packet, &unix.SockaddrInet4{Port: opts.ServerPort, Addr: dst})
}

func darwinSendIPv6(ctx context.Context, opts SendOptions, remote *net.TCPAddr) error {
	localIP, err := outboundIPv6(remote)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return darwinRawSocketError("tcp-syn knock", err)
	}
	defer unix.Close(fd)
	srcPort, err := randomEphemeralPort()
	if err != nil {
		return err
	}
	packet, err := buildSYNPacketIPv6(localIP, remote.IP.To16(), srcPort, opts.ServerPort, ComputeSYNFields(opts.Secret, opts.ClientID, opts.ServerPort, SlotFor(time.Now(), opts.TimeWindow)))
	if err != nil {
		return err
	}
	var dst [16]byte
	copy(dst[:], remote.IP.To16())
	addr := &unix.SockaddrInet6{Port: opts.ServerPort, Addr: dst}
	if remote.Zone != "" {
		if iface, err := net.InterfaceByName(remote.Zone); err == nil {
			addr.ZoneId = uint32(iface.Index)
		}
	}
	return sendSockaddr(ctx, fd, packet, addr)
}

func darwinSendSYNSequenceIPv4(ctx context.Context, opts SendOptions, remote *net.TCPAddr, seq SequenceOptions) error {
	localIP, err := outboundIPv4(remote)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return darwinRawSocketError("tcp-syn-seq knock", err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return err
	}
	var dst [4]byte
	copy(dst[:], remote.IP.To4())
	addr := &unix.SockaddrInet4{Addr: dst}
	parts := ComputeSYNSeqParts(opts.Secret, opts.ClientID, opts.ServerPort, time.Now().Unix()/int64(seq.SlotSeconds), seq.Length)
	for i, part := range parts {
		srcPort, err := randomEphemeralPort()
		if err != nil {
			return err
		}
		packet, err := buildSYNPacket(localIP, remote.IP.To4(), srcPort, part.Port, part.Fields)
		if err != nil {
			return err
		}
		addr.Port = part.Port
		if err := sendSockaddr(ctx, fd, packet, addr); err != nil {
			return err
		}
		if err := sleepSequenceInterval(ctx, i, len(parts), seq); err != nil {
			return err
		}
	}
	return nil
}

func darwinSendSYNSequenceIPv6(ctx context.Context, opts SendOptions, remote *net.TCPAddr, seq SequenceOptions) error {
	localIP, err := outboundIPv6(remote)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return darwinRawSocketError("tcp-syn-seq knock", err)
	}
	defer unix.Close(fd)
	var dst [16]byte
	copy(dst[:], remote.IP.To16())
	addr := &unix.SockaddrInet6{Addr: dst}
	if remote.Zone != "" {
		if iface, err := net.InterfaceByName(remote.Zone); err == nil {
			addr.ZoneId = uint32(iface.Index)
		}
	}
	parts := ComputeSYNSeqParts(opts.Secret, opts.ClientID, opts.ServerPort, time.Now().Unix()/int64(seq.SlotSeconds), seq.Length)
	for i, part := range parts {
		srcPort, err := randomEphemeralPort()
		if err != nil {
			return err
		}
		packet, err := buildSYNPacketIPv6(localIP, remote.IP.To16(), srcPort, part.Port, part.Fields)
		if err != nil {
			return err
		}
		addr.Port = part.Port
		if err := sendSockaddr(ctx, fd, packet, addr); err != nil {
			return err
		}
		if err := sleepSequenceInterval(ctx, i, len(parts), seq); err != nil {
			return err
		}
	}
	return nil
}

func Listen(ctx context.Context, opts ListenOptions, handler Handler) error {
	ctx = backgroundIfNil(ctx)
	if err := ValidateClientSecrets(opts.Clients); err != nil {
		return err
	}
	if opts.TimeWindow <= 0 {
		opts.TimeWindow = 30 * time.Second
	}
	if opts.Port < 1 || opts.Port > 65535 {
		return fmt.Errorf("invalid knock listen port %d", opts.Port)
	}
	replay := replayCache(opts)
	return darwinListenBPF(ctx, func(frame []byte) {
		src, fields, ok := parseSYNKnock(frame, opts.Port)
		if !ok {
			return
		}
		if opts.AllowPacket != nil && !opts.AllowPacket(src) {
			return
		}
		clientID, ok := VerifySYNFields(fields, opts.Clients, opts.Port, time.Now(), opts.TimeWindow)
		if !ok {
			return
		}
		if err := CheckSYNReplay(replay, clientID, fields, opts.Port); err != nil {
			return
		}
		handler(Event{SourceIP: src, ClientID: clientID, Method: TCPSYNMethod})
	})
}

func ListenSYNSequence(ctx context.Context, opts ListenOptions, handler Handler) error {
	ctx = backgroundIfNil(ctx)
	if err := ValidateClientSecrets(opts.Clients); err != nil {
		return err
	}
	seq := normalizedSequenceOptions(opts.Sequence)
	if opts.Port < 1 || opts.Port > 65535 {
		return fmt.Errorf("invalid protected port %d", opts.Port)
	}
	tracker := newSYNSequenceTracker(seq, opts.ReplayCache)
	return darwinListenBPF(ctx, func(frame []byte) {
		src, dstPort, fields, ok := parseSYNPacket(frame)
		if !ok {
			return
		}
		if opts.AllowPacket != nil && !opts.AllowPacket(src) {
			return
		}
		complete, clientID := tracker.add(src, dstPort, fields, opts.Clients, opts.Port, time.Now())
		if complete {
			handler(Event{SourceIP: src, ClientID: clientID, Method: TCP_SYNSeqMethod, Parts: seq.Length})
		}
	})
}

func CheckServerPrivileges() error {
	if os.Geteuid() == 0 || readableBPFDeviceExists() {
		return nil
	}
	return errors.New("macOS passive knock server requires root or read/write permission on /dev/bpf*; grant BPF permission or run as root")
}

func darwinListenBPF(ctx context.Context, onFrame func([]byte)) error {
	ctx = backgroundIfNil(ctx)
	fd, err := openBPFDevice()
	if err != nil {
		return err
	}
	defer newManagedFD(ctx, fd).Close()
	if err := syscall.CheckBpfVersion(fd); err != nil {
		return err
	}
	bufLen, err := syscall.SetBpfBuflen(fd, bpfReadBufferLen)
	if err != nil {
		return err
	}
	if err := attachBPFToBestInterface(fd); err != nil {
		return err
	}
	if err := syscall.SetBpfImmediate(fd, 1); err != nil {
		return err
	}
	buf := make([]byte, bufLen)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		for off := 0; off+unix.SizeofBpfHdr <= n; {
			hdr := (*unix.BpfHdr)(unsafe.Pointer(&buf[off]))
			start := off + int(hdr.Hdrlen)
			end := start + int(hdr.Caplen)
			if start < off || end < start || end > n {
				break
			}
			onFrame(buf[start:end])
			next := bpfWordAlign(int(hdr.Hdrlen) + int(hdr.Caplen))
			if next <= 0 {
				break
			}
			off += next
		}
	}
}

func openBPFDevice() (int, error) {
	var last error
	for i := 0; i < 255; i++ {
		fd, err := unix.Open(fmt.Sprintf("/dev/bpf%d", i), unix.O_RDWR, 0)
		if err == nil {
			return fd, nil
		}
		last = err
	}
	if last == nil {
		last = unix.ENOENT
	}
	if errors.Is(last, unix.EPERM) || errors.Is(last, unix.EACCES) {
		return -1, errors.New("macOS passive knock listener requires root or read/write permission on /dev/bpf*")
	}
	return -1, last
}

func attachBPFToBestInterface(fd int) error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	var last error
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if err := syscall.SetBpfInterface(fd, iface.Name); err == nil {
			return nil
		} else {
			last = err
		}
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if err := syscall.SetBpfInterface(fd, iface.Name); err == nil {
			return nil
		} else {
			last = err
		}
	}
	if last != nil {
		return fmt.Errorf("could not attach BPF device to an interface: %w", last)
	}
	return errors.New("could not attach BPF device: no usable network interface")
}

func readableBPFDeviceExists() bool {
	fd, err := openBPFDevice()
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}

func sendSockaddr(ctx context.Context, fd int, packet []byte, addr unix.Sockaddr) error {
	ctx = backgroundIfNil(ctx)
	errCh := make(chan error, 1)
	go func() { errCh <- unix.Sendto(fd, packet, 0, addr) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func darwinRawSocketError(feature string, err error) error {
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		return fmt.Errorf("%s on macOS requires root/raw socket permission; run as root or switch knock.method to udp/udp-seq", feature)
	}
	return err
}

func bpfWordAlign(n int) int {
	return (n + int(unsafe.Sizeof(uintptr(0))) - 1) &^ (int(unsafe.Sizeof(uintptr(0))) - 1)
}

var _ = syscall.AF_UNSPEC
