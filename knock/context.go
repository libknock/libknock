package knock

import "context"

func backgroundIfNil(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
