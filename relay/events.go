package relay

import "github.com/libknock/libknock/internal/gatewaycore"

func (g *Gateway) emitKnockOK(ev KnockEvent) {
	gatewaycore.EventEmitter{Sink: g.Events}.KnockOK(ev)
}
func (g *Gateway) emitKnockFail(ev KnockFailEvent) {
	gatewaycore.EventEmitter{Sink: g.Events}.KnockFail(ev)
}
func (g *Gateway) emitFirewallError(ev FirewallErrorEvent) {
	gatewaycore.EventEmitter{Sink: g.Events}.FirewallError(ev)
}
func (g *Gateway) emitRelayOK(ev RelayEvent) {
	gatewaycore.EventEmitter{Sink: g.Events}.RelayOK(ev)
}
func (g *Gateway) emitRelayError(ev RelayErrorEvent) {
	gatewaycore.EventEmitter{Sink: g.Events}.RelayError(ev)
}
