package knock

import (
	"context"

	"github.com/libknock/libknock/auth"
)

type Sender = auth.KnockSender

type NoopSender struct{}

func (NoopSender) Knock(ctx context.Context) error { return nil }
