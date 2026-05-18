//go:build !linux && !windows && !darwin

package knock

import "context"

func Send(ctx context.Context, opts SendOptions) error                      { return ErrUnsupported }
func Listen(ctx context.Context, opts ListenOptions, handler Handler) error { return ErrUnsupported }
