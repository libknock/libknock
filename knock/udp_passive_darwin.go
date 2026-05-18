//go:build darwin

package knock

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"
)

func ListenUDPPassive(ctx context.Context, opts ListenOptions, handler Handler) error {
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
	if err := ValidateClientSecrets(opts.Clients); err != nil {
		return err
	}
	replay := replayCache(opts)
	maxFrameSize := maxKnockFrameSize(opts)
	return darwinListenBPF(ctx, func(packet []byte) {
		src, payload, ok := parseUDPKnockDatagram(packet, knockPort)
		if !ok || len(payload) > maxFrameSize {
			return
		}
		if opts.AllowPacket != nil && !opts.AllowPacket(src) {
			return
		}
		info, err := OpenKnockFrame(payload, ServerConfig{Clients: opts.Clients, ServerPort: opts.Port, Method: UDPPassiveMethod, TimeWindow: opts.TimeWindow, MaxFrameSize: maxFrameSize, ReplayCache: replay})
		if err != nil {
			return
		}
		if err := requireKnockSessionID(opts, info); err != nil {
			return
		}
		handler(Event{SourceIP: src, ClientID: info.ClientID, Nonce: hex.EncodeToString(info.Nonce), Method: UDPPassiveMethod, SessionID: info.SessionID})
	})
}

func ListenUDPPassiveSequence(ctx context.Context, opts ListenOptions, handler Handler) error {
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
	if err := ValidateClientSecrets(opts.Clients); err != nil {
		return err
	}
	tracker := newSequenceTracker(opts.Sequence, opts.NonceTTL)
	replay := replayCache(opts)
	maxFrameSize := maxKnockFrameSize(opts)
	return darwinListenBPF(ctx, func(packet []byte) {
		src, payload, ok := parseUDPKnockDatagram(packet, knockPort)
		if !ok || len(payload) > maxFrameSize {
			return
		}
		if opts.AllowPacket != nil && !opts.AllowPacket(src) {
			return
		}
		info, err := OpenKnockFrame(payload, ServerConfig{Clients: opts.Clients, ServerPort: opts.Port, Method: UDPPassiveSeq, TimeWindow: opts.TimeWindow, MaxFrameSize: maxFrameSize, ReplayCache: replay, AllowSequence: true})
		if err != nil {
			return
		}
		if err := requireKnockSessionID(opts, info); err != nil {
			return
		}
		complete, err := tracker.add(src, info, time.Now())
		if err != nil || !complete {
			return
		}
		handler(Event{SourceIP: src, ClientID: info.ClientID, Nonce: hex.EncodeToString(info.Nonce), Method: UDPPassiveSeq, Parts: info.SequenceTotal, SessionID: info.SessionID})
	})
}
