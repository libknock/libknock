package knock

import (
	"context"
	"fmt"
)

const (
	UDPMethod           = "udp"
	UDPPassiveMethod    = "udp-passive"
	TCPSYNMethod        = "tcp-syn"
	UDPSeqMethodName    = UDPSeqMethod
	UDPPassiveSeqMethod = UDPPassiveSeq
	TCPSYNSeqMethodName = TCP_SYNSeqMethod
)

func SendMethod(ctx context.Context, method string, opts SendOptions) error {
	ctx = backgroundIfNil(ctx)
	method = NormalizeMethod(method)
	switch method {
	case UDPMethod:
		return SendUDPMethod(ctx, opts, UDPMethod)
	case UDPPassiveMethod:
		return SendUDPMethod(ctx, opts, UDPPassiveMethod)
	case UDPSeqMethod:
		return SendUDPSequenceMethod(ctx, opts, UDPSeqMethod)
	case UDPPassiveSeq:
		return SendUDPSequenceMethod(ctx, opts, UDPPassiveSeq)
	case TCPSYNMethod:
		if err := CheckClientSupport(method); err != nil {
			return err
		}
		return Send(ctx, opts)
	case TCP_SYNSeqMethod:
		if err := CheckClientSupport(method); err != nil {
			return err
		}
		return SendSYNSequence(ctx, opts)
	default:
		return fmt.Errorf("unsupported knock method %q", method)
	}
}

func SendUDPPassiveSequence(ctx context.Context, opts SendOptions) error {
	return SendUDPSequenceMethod(ctx, opts, UDPPassiveSeq)
}
