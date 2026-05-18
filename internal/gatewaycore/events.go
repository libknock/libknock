package gatewaycore

import "github.com/libknock/libknock/observability"

type EventEmitter struct{ Sink observability.GatewayEvents }

func (e EventEmitter) KnockOK(ev observability.KnockEvent) {
	if e.Sink != nil {
		e.Sink.OnKnockOK(ev)
	}
}
func (e EventEmitter) KnockFail(ev observability.KnockFailEvent) {
	if e.Sink != nil {
		e.Sink.OnKnockFail(ev)
	}
}
func (e EventEmitter) FirewallAllow(ev observability.FirewallEvent) {
	if e.Sink != nil {
		e.Sink.OnFirewallAllow(ev)
	}
}
func (e EventEmitter) FirewallError(ev observability.FirewallErrorEvent) {
	if e.Sink != nil {
		e.Sink.OnFirewallError(ev)
	}
}
func (e EventEmitter) RelayOK(ev observability.RelayEvent) {
	if e.Sink != nil {
		e.Sink.OnRelayOK(ev)
	}
}
func (e EventEmitter) RelayError(ev observability.RelayErrorEvent) {
	if e.Sink != nil {
		e.Sink.OnRelayError(ev)
	}
}
