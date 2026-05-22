//go:build linux

package knock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

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
		return sendSYNSequenceIPv4(ctx, opts, remote, seq)
	}
	return sendSYNSequenceIPv6(ctx, opts, remote, seq)
}

func sendSYNSequenceIPv4(ctx context.Context, opts SendOptions, remote *net.TCPAddr, seq SequenceOptions) error {
	localIP, err := outboundIPv4(remote)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return errors.New("tcp-syn-seq knock requires CAP_NET_RAW or root")
		}
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return err
	}
	parts := ComputeSYNSeqParts(opts.Secret, opts.ClientID, opts.ServerPort, time.Now().Unix()/int64(seq.SlotSeconds), seq.Length)
	var dst [4]byte
	copy(dst[:], remote.IP.To4())
	addr := &unix.SockaddrInet4{Addr: dst}
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
		errCh := make(chan error, 1)
		go func() { errCh <- unix.Sendto(fd, packet, 0, addr) }()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			if err != nil {
				return err
			}
		}
		if err := sleepSequenceInterval(ctx, i, len(parts), seq); err != nil {
			return err
		}
	}
	return nil
}

func sendSYNSequenceIPv6(ctx context.Context, opts SendOptions, remote *net.TCPAddr, seq SequenceOptions) error {
	localIP, err := outboundIPv6(remote)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return errors.New("tcp-syn-seq knock requires CAP_NET_RAW or root")
		}
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
		return err
	}
	parts := ComputeSYNSeqParts(opts.Secret, opts.ClientID, opts.ServerPort, time.Now().Unix()/int64(seq.SlotSeconds), seq.Length)
	var dst [16]byte
	copy(dst[:], remote.IP.To16())
	addr := &unix.SockaddrInet6{Addr: dst}
	if remote.Zone != "" {
		if iface, err := net.InterfaceByName(remote.Zone); err == nil {
			addr.ZoneId = uint32(iface.Index)
		}
	}
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
		errCh := make(chan error, 1)
		go func() { errCh <- unix.Sendto(fd, packet, 0, addr) }()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			if err != nil {
				return err
			}
		}
		if err := sleepSequenceInterval(ctx, i, len(parts), seq); err != nil {
			return err
		}
	}
	return nil
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
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return errors.New("tcp-syn-seq server requires CAP_NET_ADMIN and CAP_NET_RAW, or must be run as root")
		}
		return err
	}
	defer newManagedFD(ctx, fd).Close()
	tracker := newSYNSequenceTracker(seq, opts.ReplayCache)
	buf := make([]byte, 65535)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		src, dstPort, fields, ok := parseSYNPacket(buf[:n])
		if !ok {
			continue
		}
		if opts.AllowPacket != nil && !opts.AllowPacket(src) {
			continue
		}
		complete, clientID := tracker.add(src, dstPort, fields, opts.Clients, opts.Port, time.Now())
		if complete {
			handler(Event{SourceIP: src, ClientID: clientID, Method: TCP_SYNSeqMethod, Parts: seq.Length})
		}
	}
}

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
		return sendIPv4(ctx, opts, remote)
	}
	return sendIPv6(ctx, opts, remote)
}

func sendIPv4(ctx context.Context, opts SendOptions, remote *net.TCPAddr) error {
	localIP, err := outboundIPv4(remote)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return errors.New("tcp-syn knock requires CAP_NET_RAW or root")
		}
		return err
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
	addr := &unix.SockaddrInet4{Port: opts.ServerPort, Addr: dst}
	errCh := make(chan error, 1)
	go func() { errCh <- unix.Sendto(fd, packet, 0, addr) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func sendIPv6(ctx context.Context, opts SendOptions, remote *net.TCPAddr) error {
	localIP, err := outboundIPv6(remote)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return errors.New("tcp-syn knock requires CAP_NET_RAW or root")
		}
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
		return err
	}
	fields := ComputeSYNFields(opts.Secret, opts.ClientID, opts.ServerPort, SlotFor(time.Now(), opts.TimeWindow))
	srcPort, err := randomEphemeralPort()
	if err != nil {
		return err
	}
	packet, err := buildSYNPacketIPv6(localIP, remote.IP.To16(), srcPort, opts.ServerPort, fields)
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
	errCh := make(chan error, 1)
	go func() { errCh <- unix.Sendto(fd, packet, 0, addr) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
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
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return errors.New("server requires CAP_NET_ADMIN and CAP_NET_RAW, or must be run as root")
		}
		return err
	}
	defer newManagedFD(ctx, fd).Close()
	buf := make([]byte, 65535)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		src, fields, ok := parseSYNKnock(buf[:n], opts.Port)
		if !ok {
			continue
		}
		if opts.AllowPacket != nil && !opts.AllowPacket(src) {
			continue
		}
		clientID, ok := VerifySYNFields(fields, opts.Clients, opts.Port, time.Now(), opts.TimeWindow)
		if !ok {
			continue
		}
		if err := CheckSYNReplay(replay, clientID, fields, opts.Port); err != nil {
			continue
		}
		handler(Event{SourceIP: src, ClientID: clientID, Method: "tcp-syn"})
	}
}

func CheckServerPrivileges() error {
	if os.Geteuid() == 0 {
		return nil
	}
	if hasEffectiveCaps(12, 13) {
		return nil
	}
	return errors.New("server requires CAP_NET_ADMIN and CAP_NET_RAW, or must be run as root")
}

func hasEffectiveCaps(required ...uint) bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return false
		}
		value, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			return false
		}
		for _, capNo := range required {
			if value&(uint64(1)<<capNo) == 0 {
				return false
			}
		}
		return true
	}
	return false
}
