package relay

import (
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/firewall"
	"github.com/libknock/libknock/knock"
	"github.com/libknock/libknock/observability"
)

type Gateway struct {
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
	// MaxPendingAuthPerSource caps queued/in-progress auths per source (IPv4
	// address or IPv6 /64). Zero or negative disables (opt-in; see netx).
	MaxPendingAuthPerSource int
	// EnableMPTCP lets the gateway listener accept Multipath TCP. Off by
	// default because subflows joined from other addresses bypass source
	// binding, policy and per-source limits; enable only with a firewall mode.
	EnableMPTCP bool
	Events      EventSink
}

type EventSink = observability.GatewayEvents
type KnockEvent = observability.KnockEvent
type KnockFailEvent = observability.KnockFailEvent
type FirewallEvent = observability.FirewallEvent
type FirewallErrorEvent = observability.FirewallErrorEvent
type RelayEvent = observability.RelayEvent
type RelayErrorEvent = observability.RelayErrorEvent
