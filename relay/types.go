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
	Events                 EventSink
}

type EventSink = observability.GatewayEvents
type KnockEvent = observability.KnockEvent
type KnockFailEvent = observability.KnockFailEvent
type FirewallEvent = observability.FirewallEvent
type FirewallErrorEvent = observability.FirewallErrorEvent
type RelayEvent = observability.RelayEvent
type RelayErrorEvent = observability.RelayErrorEvent
