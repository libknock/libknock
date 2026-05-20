//go:build linux

package knock

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

func ListenUDPPassiveSequence(ctx context.Context, opts ListenOptions, handler Handler) error {
	ctx = backgroundIfNil(ctx)
	if opts.Port < 1 || opts.Port > 65535 {
		return fmt.Errorf("invalid protected port %d", opts.Port)
	}
	knockPort := opts.KnockPort
	if knockPort == 0 {
		knockPort = opts.Port
	}
	if knockPort < 1 || knockPort > 65535 {
		return fmt.Errorf("invalid udp knock port %d", knockPort)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return errors.New("udp-passive-seq server requires CAP_NET_ADMIN and CAP_NET_RAW, or must be run as root")
		}
		return err
	}
	defer unix.Close(fd)
	go func() { <-ctx.Done(); _ = unix.Close(fd) }()
	if err := ValidateClientSecrets(opts.Clients); err != nil {
		return err
	}
	tracker := newSequenceTracker(opts.Sequence, opts.NonceTTL)
	replay := replayCache(opts)
	maxFrameSize := maxKnockFrameSize(opts)
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
		src, payload, ok := parseUDPKnockDatagram(buf[:n], knockPort)
		if !ok || len(payload) > maxFrameSize {
			continue
		}
		if opts.AllowPacket != nil && !opts.AllowPacket(src) {
			continue
		}
		info, err := OpenKnockFrame(payload, ServerConfig{Clients: opts.Clients, ServerPort: opts.Port, Method: UDPPassiveSeq, TimeWindow: opts.TimeWindow, MaxFrameSize: maxFrameSize, ReplayCache: replay, AllowSequence: true})
		if err != nil {
			continue
		}
		if err := requireKnockSessionID(opts, info); err != nil {
			continue
		}
		complete, err := tracker.add(src, info, time.Now())
		if err != nil {
			continue
		}
		if complete {
			handler(Event{SourceIP: src, ClientID: info.ClientID, Nonce: hex.EncodeToString(info.Nonce), Method: UDPPassiveSeq, Parts: info.SequenceTotal, SessionID: info.SessionID})
		}
	}
}

func ListenUDPPassive(ctx context.Context, opts ListenOptions, handler Handler) error {
	ctx = backgroundIfNil(ctx)
	if opts.TimeWindow <= 0 {
		opts.TimeWindow = 30 * time.Second
	}
	if opts.Port < 1 || opts.Port > 65535 {
		return fmt.Errorf("invalid protected port %d", opts.Port)
	}
	knockPort := opts.KnockPort
	if knockPort == 0 {
		knockPort = opts.Port
	}
	if knockPort < 1 || knockPort > 65535 {
		return fmt.Errorf("invalid udp knock port %d", knockPort)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return errors.New("udp-passive server requires CAP_NET_ADMIN and CAP_NET_RAW, or must be run as root")
		}
		return err
	}
	defer unix.Close(fd)
	go func() { <-ctx.Done(); _ = unix.Close(fd) }()
	if err := ValidateClientSecrets(opts.Clients); err != nil {
		return err
	}
	replay := replayCache(opts)
	maxFrameSize := maxKnockFrameSize(opts)
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
		src, payload, ok := parseUDPKnockDatagram(buf[:n], knockPort)
		if !ok || len(payload) > maxFrameSize {
			continue
		}
		if opts.AllowPacket != nil && !opts.AllowPacket(src) {
			continue
		}
		info, err := OpenKnockFrame(payload, ServerConfig{Clients: opts.Clients, ServerPort: opts.Port, Method: UDPPassiveMethod, TimeWindow: opts.TimeWindow, MaxFrameSize: maxFrameSize, ReplayCache: replay})
		if err != nil {
			continue
		}
		if err := requireKnockSessionID(opts, info); err != nil {
			continue
		}
		handler(Event{SourceIP: src, ClientID: info.ClientID, Nonce: hex.EncodeToString(info.Nonce), Method: UDPPassiveMethod, SessionID: info.SessionID})
	}
}
