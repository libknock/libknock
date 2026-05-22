package relay

import (
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/knock"
)

// Config is the preferred construction surface for Gateway. The Gateway struct
// remains public for v0.1.x compatibility, but new integrations should call
// NewGateway(cfg) so relay defaults stay explicit and auditable.
type Config struct {
	Listen                 string
	Upstream               string
	Auth                   auth.ServerConfig
	Firewall               firewall.Backend
	KnockMethod            string
	KnockListen            string
	KnockPort              int
	KnockClients           []knock.ClientSecret
	KnockTimeWindow        time.Duration
	KnockMaxFrameSize      int
	KnockSequence          knock.SequenceOptions
	KnockNonceTTL          time.Duration
	AllowTTL               time.Duration
	UpstreamConnectTimeout time.Duration
	IdleTimeout            time.Duration
	RemoveAfterAuth        bool
	MaxConnectionsPerKnock int
	DisableSessionBinding  bool
	MaxPendingAuth         int
	MaxAuthWorkers         int
	Events                 EventSink
}

func (c Config) WithDefaults() Config {
	if c.Firewall == nil {
		c.Firewall = firewall.Noop{}
	}
	if c.AllowTTL <= 0 {
		c.AllowTTL = time.Minute
	}
	if c.UpstreamConnectTimeout <= 0 {
		c.UpstreamConnectTimeout = 5 * time.Second
	}
	if c.MaxPendingAuth <= 0 {
		c.MaxPendingAuth = 128
	}
	if c.MaxAuthWorkers <= 0 {
		c.MaxAuthWorkers = 32
	}
	return c
}

func NewGateway(cfg Config) *Gateway {
	cfg = cfg.WithDefaults()
	return &Gateway{
		Listen: cfg.Listen, Upstream: cfg.Upstream, Auth: cfg.Auth, Firewall: cfg.Firewall,
		KnockMethod: cfg.KnockMethod, KnockListen: cfg.KnockListen, KnockPort: cfg.KnockPort,
		KnockClients: cfg.KnockClients, KnockTimeWindow: cfg.KnockTimeWindow, KnockMaxFrameSize: cfg.KnockMaxFrameSize,
		KnockSequence: cfg.KnockSequence, KnockNonceTTL: cfg.KnockNonceTTL, AllowTTL: cfg.AllowTTL,
		UpstreamConnectTimeout: cfg.UpstreamConnectTimeout, IdleTimeout: cfg.IdleTimeout,
		RemoveAfterAuth: cfg.RemoveAfterAuth, MaxConnectionsPerKnock: cfg.MaxConnectionsPerKnock,
		DisableSessionBinding: cfg.DisableSessionBinding, MaxPendingAuth: cfg.MaxPendingAuth,
		MaxAuthWorkers: cfg.MaxAuthWorkers, Events: cfg.Events,
	}
}
