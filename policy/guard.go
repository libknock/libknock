package policy

import "time"

type Guard struct {
	Limiter *Limiter
	Bans    *BanList
	BanTTL  time.Duration
}

func NewGuard(window Window, banTTL time.Duration) *Guard {
	return &Guard{Limiter: NewLimiter(window), Bans: NewBanList(), BanTTL: banTTL}
}

func (g *Guard) Allow(key string) bool {
	if g == nil {
		return true
	}
	if g.Bans != nil && g.Bans.IsBanned(key) {
		return false
	}
	if g.Limiter != nil && !g.Limiter.Allow(key) {
		if g.Bans != nil && g.BanTTL > 0 {
			g.Bans.Ban(key, g.BanTTL)
		}
		return false
	}
	return true
}

func (g *Guard) Check(key string) error {
	if g.Allow(key) {
		return nil
	}
	return ErrRateLimited
}
