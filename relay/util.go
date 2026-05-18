package relay

import "time"

func nonzero(v, d time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return d
}
func (g *Gateway) maxPendingAuth() int {
	if g.MaxPendingAuth > 0 {
		return g.MaxPendingAuth
	}
	return 128
}
func (g *Gateway) maxAuthWorkers() int {
	if g.MaxAuthWorkers > 0 {
		return g.MaxAuthWorkers
	}
	return 32
}
