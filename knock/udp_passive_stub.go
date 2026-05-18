//go:build !linux && !windows && !darwin

package knock

import "context"

func ListenUDPPassive(ctx context.Context, opts ListenOptions, handler Handler) error {
	return ErrUnsupported
}
func ListenUDPPassiveSequence(ctx context.Context, opts ListenOptions, handler Handler) error {
	return ErrUnsupported
}
