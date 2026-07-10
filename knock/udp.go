package knock

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

func SendUDP(ctx context.Context, opts SendOptions) error { return SendUDPMethod(ctx, opts, "udp") }

func SendUDPMethod(ctx context.Context, opts SendOptions, method string) error {
	ctx = backgroundIfNil(ctx)
	if opts.TimeWindow <= 0 {
		opts.TimeWindow = 30 * time.Second
	}
	data, err := BuildKnockFrame(KnockFrameOptions{ClientID: opts.ClientID, Secret: opts.Secret, ServerPort: opts.ServerPort, Method: method, SessionID: opts.SessionID, MaxFrameSize: opts.MaxFrameSize})
	if err != nil {
		return err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", opts.ServerAddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(deadline)
	}
	_, err = conn.Write(data)
	return err
}

type KnockListener interface {
	Serve(ctx context.Context, handler Handler) error
	Close() error
}

type udpListener struct {
	conn net.PacketConn
	opts ListenOptions
}

func NewUDPListener(listen string, opts ListenOptions) (KnockListener, error) {
	if listen == "" {
		return nil, fmt.Errorf("udp listen address is required")
	}
	if err := ValidateClientSecrets(opts.Clients); err != nil {
		return nil, err
	}
	conn, err := net.ListenPacket("udp", listen)
	if err != nil {
		return nil, err
	}
	return &udpListener{conn: conn, opts: opts}, nil
}

func (l *udpListener) Close() error   { return l.conn.Close() }
func (l *udpListener) Addr() net.Addr { return l.conn.LocalAddr() }

func (l *udpListener) Serve(ctx context.Context, handler Handler) error {
	ctx = backgroundIfNil(ctx)
	defer l.Close()
	// The context watcher must also stop when ReadFrom returns for a reason
	// other than context cancellation. Otherwise a failed listener leaves one
	// goroutine blocked on a context that its caller may retain indefinitely.
	serveDone := make(chan struct{})
	defer close(serveDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = l.Close()
		case <-serveDone:
		}
	}()
	opts := l.opts
	replay := replayCache(opts)
	maxFrameSize := maxKnockFrameSize(opts)
	buf := make([]byte, maxFrameSize)
	for {
		n, addr, err := l.conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok || udpAddr.IP == nil {
			continue
		}
		if !allowKnockPacket(opts, udpAddr.IP) {
			continue
		}
		info, err := OpenKnockFrame(buf[:n], ServerConfig{Clients: opts.Clients, ServerPort: opts.Port, Method: UDPMethod, TimeWindow: opts.TimeWindow, MaxFrameSize: maxFrameSize, ReplayCache: replay})
		if err != nil {
			if opts.InvalidPacket != nil {
				opts.InvalidPacket(udpAddr.IP, err.Error())
			}
			continue
		}
		if err := requireKnockSessionID(opts, info); err != nil {
			if opts.InvalidPacket != nil {
				opts.InvalidPacket(udpAddr.IP, err.Error())
			}
			continue
		}
		handler(Event{SourceIP: udpAddr.IP, ClientID: info.ClientID, Nonce: hex.EncodeToString(info.Nonce), Method: UDPMethod, SessionID: info.SessionID})
	}
}

func allowKnockPacket(opts ListenOptions, ip net.IP) bool {
	if opts.AllowPacket != nil && !opts.AllowPacket(ip) {
		return false
	}
	if opts.PacketLimiter != nil && !opts.PacketLimiter.Allow(ip) {
		if opts.InvalidPacket != nil {
			opts.InvalidPacket(ip, "packet_rate_limited")
		}
		return false
	}
	return true
}

func ListenUDP(ctx context.Context, listen string, opts ListenOptions, handler Handler) error {
	listener, err := NewUDPListener(listen, opts)
	if err != nil {
		return err
	}
	return listener.Serve(ctx, handler)
}

func maxKnockFrameSize(opts ListenOptions) int {
	if opts.MaxFrameSize > 0 {
		return opts.MaxFrameSize
	}
	return DefaultMaxKnockFrameSize
}

func requireKnockSessionID(opts ListenOptions, info *KnockInfo) error {
	if !opts.RequireSessionID {
		return nil
	}
	if info == nil {
		return requireSessionID(nil)
	}
	return requireSessionID(info.SessionID)
}
