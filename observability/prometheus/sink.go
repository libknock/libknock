// Package prometheus provides an optional Prometheus adapter for libknock events.
package prometheus

import (
	"errors"
	"net"
	"strings"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/observability"
	prom "github.com/prometheus/client_golang/prometheus"
)

const defaultNamespace = "libknock"

type Config struct {
	Namespace            string
	ConstLabels          prom.Labels
	Registerer           prom.Registerer
	IncludeClientLabel   bool
	RelayDurationBuckets []float64
}

type Sink struct {
	includeClient    bool
	authAccept       prom.Counter
	authOK           *prom.CounterVec
	authFail         *prom.CounterVec
	authReplay       prom.Counter
	authReplayFull   prom.Counter
	replayCacheLen   prom.Gauge
	replayCacheCap   prom.Gauge
	authRateLimited  prom.Counter
	knockOK          *prom.CounterVec
	knockFail        *prom.CounterVec
	firewallAllow    prom.Counter
	firewallError    prom.Counter
	relayOK          *prom.CounterVec
	relayError       *prom.CounterVec
	relayRX          *prom.CounterVec
	relayTX          *prom.CounterVec
	relayDuration    *prom.HistogramVec
	relayPendingFull prom.Counter
	relayDropped     prom.Counter
	relayPending     prom.Gauge
}

var _ observability.EventSink = (*Sink)(nil)

func New(cfg Config) (*Sink, error) {
	namespace := strings.TrimSpace(cfg.Namespace)
	if namespace == "" {
		namespace = defaultNamespace
	}
	buckets := cfg.RelayDurationBuckets
	if len(buckets) == 0 {
		buckets = prom.DefBuckets
	}
	clientLabels := []string{}
	if cfg.IncludeClientLabel {
		clientLabels = []string{"client_id"}
	}
	s := &Sink{includeClient: cfg.IncludeClientLabel}
	s.authAccept = prom.NewCounter(prom.CounterOpts{Namespace: namespace, Subsystem: "auth", Name: "accept_total", Help: "Total TCP connections accepted for libknock authentication.", ConstLabels: cfg.ConstLabels})
	s.authOK = prom.NewCounterVec(prom.CounterOpts{Namespace: namespace, Subsystem: "auth", Name: "success_total", Help: "Total successful libknock authentications.", ConstLabels: cfg.ConstLabels}, append([]string{"method"}, clientLabels...))
	s.authFail = prom.NewCounterVec(prom.CounterOpts{Namespace: namespace, Subsystem: "auth", Name: "failure_total", Help: "Total failed libknock authentications by normalized reason.", ConstLabels: cfg.ConstLabels}, []string{"reason"})
	s.authReplay = prom.NewCounter(prom.CounterOpts{Namespace: namespace, Subsystem: "auth", Name: "replay_total", Help: "Total replay attempts observed by libknock authentication.", ConstLabels: cfg.ConstLabels})
	s.authReplayFull = prom.NewCounter(prom.CounterOpts{Namespace: namespace, Subsystem: "auth", Name: "replay_cache_full_total", Help: "Total authentication attempts rejected because the replay cache was full.", ConstLabels: cfg.ConstLabels})
	s.replayCacheLen = prom.NewGauge(prom.GaugeOpts{Namespace: namespace, Subsystem: "auth", Name: "replay_cache_len", Help: "Last observed active replay cache entries after a full-cache rejection.", ConstLabels: cfg.ConstLabels})
	s.replayCacheCap = prom.NewGauge(prom.GaugeOpts{Namespace: namespace, Subsystem: "auth", Name: "replay_cache_capacity", Help: "Last observed replay cache capacity after a full-cache rejection.", ConstLabels: cfg.ConstLabels})
	s.authRateLimited = prom.NewCounter(prom.CounterOpts{Namespace: namespace, Subsystem: "auth", Name: "rate_limited_total", Help: "Total authentication attempts rejected by policy rate limits.", ConstLabels: cfg.ConstLabels})
	s.knockOK = prom.NewCounterVec(prom.CounterOpts{Namespace: namespace, Subsystem: "knock", Name: "success_total", Help: "Total successful knock events.", ConstLabels: cfg.ConstLabels}, append([]string{"method"}, clientLabels...))
	s.knockFail = prom.NewCounterVec(prom.CounterOpts{Namespace: namespace, Subsystem: "knock", Name: "failure_total", Help: "Total failed knock events by normalized reason.", ConstLabels: cfg.ConstLabels}, append([]string{"reason"}, clientLabels...))
	s.firewallAllow = prom.NewCounter(prom.CounterOpts{Namespace: namespace, Subsystem: "firewall", Name: "allow_total", Help: "Total firewall allow operations requested by libknock.", ConstLabels: cfg.ConstLabels})
	s.firewallError = prom.NewCounter(prom.CounterOpts{Namespace: namespace, Subsystem: "firewall", Name: "error_total", Help: "Total firewall operation errors observed by libknock.", ConstLabels: cfg.ConstLabels})
	s.relayOK = prom.NewCounterVec(prom.CounterOpts{Namespace: namespace, Subsystem: "relay", Name: "success_total", Help: "Total successful relay sessions.", ConstLabels: cfg.ConstLabels}, clientLabels)
	s.relayError = prom.NewCounterVec(prom.CounterOpts{Namespace: namespace, Subsystem: "relay", Name: "error_total", Help: "Total relay errors by stage.", ConstLabels: cfg.ConstLabels}, append([]string{"stage"}, clientLabels...))
	s.relayRX = prom.NewCounterVec(prom.CounterOpts{Namespace: namespace, Subsystem: "relay", Name: "rx_bytes_total", Help: "Total bytes copied from client to upstream by successful relay sessions.", ConstLabels: cfg.ConstLabels}, clientLabels)
	s.relayTX = prom.NewCounterVec(prom.CounterOpts{Namespace: namespace, Subsystem: "relay", Name: "tx_bytes_total", Help: "Total bytes copied from upstream to client by successful relay sessions.", ConstLabels: cfg.ConstLabels}, clientLabels)
	s.relayDuration = prom.NewHistogramVec(prom.HistogramOpts{Namespace: namespace, Subsystem: "relay", Name: "duration_seconds", Help: "Successful relay session duration in seconds.", ConstLabels: cfg.ConstLabels, Buckets: buckets}, clientLabels)
	s.relayPendingFull = prom.NewCounter(prom.CounterOpts{Namespace: namespace, Subsystem: "relay", Name: "pending_full_total", Help: "Total accepted connections dropped because the authentication pending queue was full.", ConstLabels: cfg.ConstLabels})
	s.relayDropped = prom.NewCounter(prom.CounterOpts{Namespace: namespace, Subsystem: "relay", Name: "dropped_total", Help: "Total relay connections dropped before authentication or upstream relay completion.", ConstLabels: cfg.ConstLabels})
	s.relayPending = prom.NewGauge(prom.GaugeOpts{Namespace: namespace, Subsystem: "relay", Name: "pending_current", Help: "Last observed authentication pending queue depth when a relay drop was reported.", ConstLabels: cfg.ConstLabels})
	if cfg.Registerer != nil {
		if err := register(cfg.Registerer, s.collectors()...); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func MustNew(cfg Config) *Sink {
	s, err := New(cfg)
	if err != nil {
		// Prometheus descriptor/registration failures are configuration bugs in the metrics surface; the Must variant preserves fail-fast startup semantics.
		panic(err)
	}
	return s
}

func (s *Sink) OnAccept(net.Addr) { s.authAccept.Inc() }
func (s *Sink) OnAuthOK(peer auth.PeerInfo) {
	s.authOK.WithLabelValues(s.authOKLabels(peer.Method, peer.ClientID)...).Inc()
}
func (s *Sink) OnAuthFail(_ net.Addr, reason error) {
	s.authFail.WithLabelValues(reasonLabel(reason)).Inc()
}
func (s *Sink) OnReplay(net.Addr, uint64) { s.authReplay.Inc() }
func (s *Sink) OnReplayCacheFull(_ net.Addr, _ uint64, length, capacity int) {
	s.authReplayFull.Inc()
	s.replayCacheLen.Set(float64(nonnegativeInt(length)))
	s.replayCacheCap.Set(float64(nonnegativeInt(capacity)))
}
func (s *Sink) OnRateLimited(net.Addr) { s.authRateLimited.Inc() }
func (s *Sink) OnKnockOK(ev observability.KnockEvent) {
	s.knockOK.WithLabelValues(s.knockOKLabels(ev.Method, ev.ClientID)...).Inc()
}
func (s *Sink) OnKnockFail(ev observability.KnockFailEvent) {
	s.knockFail.WithLabelValues(s.knockFailLabels(ev.Reason, ev.ClientID)...).Inc()
}
func (s *Sink) OnFirewallAllow(observability.FirewallEvent)      { s.firewallAllow.Inc() }
func (s *Sink) OnFirewallError(observability.FirewallErrorEvent) { s.firewallError.Inc() }
func (s *Sink) OnRelayOK(ev observability.RelayEvent) {
	labels := s.clientLabels(ev.ClientID)
	s.relayOK.WithLabelValues(labels...).Inc()
	s.relayRX.WithLabelValues(labels...).Add(float64(nonnegative(ev.RX)))
	s.relayTX.WithLabelValues(labels...).Add(float64(nonnegative(ev.TX)))
	s.relayDuration.WithLabelValues(labels...).Observe(ev.Duration.Seconds())
}
func (s *Sink) OnRelayError(ev observability.RelayErrorEvent) {
	s.relayError.WithLabelValues(s.relayErrorLabels(ev.Stage, ev.ClientID)...).Inc()
	if ev.Stage == "pending_full" {
		s.relayPendingFull.Inc()
	}
	if ev.DroppedCount > 0 {
		s.relayDropped.Add(float64(ev.DroppedCount))
	}
	if ev.Pending >= 0 {
		s.relayPending.Set(float64(ev.Pending))
	}
}

func (s *Sink) collectors() []prom.Collector {
	return []prom.Collector{s.authAccept, s.authOK, s.authFail, s.authReplay, s.authReplayFull, s.replayCacheLen, s.replayCacheCap, s.authRateLimited, s.knockOK, s.knockFail, s.firewallAllow, s.firewallError, s.relayOK, s.relayError, s.relayRX, s.relayTX, s.relayDuration, s.relayPendingFull, s.relayDropped, s.relayPending}
}
func (s *Sink) authOKLabels(method, clientID string) []string {
	return append([]string{methodLabel(method)}, s.clientLabels(clientID)...)
}
func (s *Sink) knockOKLabels(method, clientID string) []string {
	return append([]string{methodLabel(method)}, s.clientLabels(clientID)...)
}
func (s *Sink) knockFailLabels(reason, clientID string) []string {
	return append([]string{labelOrUnknown(reason)}, s.clientLabels(clientID)...)
}
func (s *Sink) relayErrorLabels(stage, clientID string) []string {
	return append([]string{labelOrUnknown(stage)}, s.clientLabels(clientID)...)
}
func (s *Sink) clientLabels(clientID string) []string {
	if !s.includeClient {
		return nil
	}
	return []string{labelOrUnknown(clientID)}
}

func register(reg prom.Registerer, collectors ...prom.Collector) error {
	for _, c := range collectors {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

func reasonLabel(err error) string {
	switch {
	case err == nil:
		return "unknown"
	case errors.Is(err, auth.ErrInvalidFrame):
		return "invalid_frame"
	case errors.Is(err, auth.ErrFrameTooLarge):
		return "frame_too_large"
	case errors.Is(err, auth.ErrUnknownClient):
		return "unknown_client"
	case errors.Is(err, auth.ErrAuthFailed):
		return "auth_failed"
	case errors.Is(err, auth.ErrReplayDetected):
		return "replay"
	case errors.Is(err, auth.ErrTimeSkew):
		return "time_skew"
	case errors.Is(err, auth.ErrKnockRequired):
		return "knock_required"
	case errors.Is(err, auth.ErrUnsupportedVersion):
		return "unsupported_version"
	case errors.Is(err, auth.ErrInvalidClientID):
		return "invalid_client_id"
	case errors.Is(err, auth.ErrInvalidSecret):
		return "invalid_secret"
	case errors.Is(err, auth.ErrMissingSecretResolver):
		return "missing_secret_resolver"
	case errors.Is(err, auth.ErrMissingReplayCache):
		return "missing_replay_cache"
	case errors.Is(err, auth.ErrRateLimited):
		return "rate_limited"
	case errors.Is(err, auth.ErrServerProofRequired):
		return "server_proof_required"
	case errors.Is(err, auth.ErrServerProofFailed):
		return "server_proof_failed"
	case errors.Is(err, auth.ErrUnsupportedFlags):
		return "unsupported_flags"
	case errors.Is(err, auth.ErrSecretResolverFailed):
		return "secret_resolver_failed"
	case errors.Is(err, auth.ErrTooManyCandidates):
		return "too_many_candidates"
	default:
		return "error"
	}
}

func methodLabel(method string) string {
	switch strings.TrimSpace(method) {
	case "tcp-auth", "tcp-syn", "tcp-syn-seq", "udp", "udp-seq", "udp-passive", "udp-passive-seq":
		return strings.TrimSpace(method)
	default:
		return "unknown"
	}
}

func labelOrUnknown(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	return v
}
func nonnegative(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

func nonnegativeInt(v int) int {
	if v < 0 {
		return 0
	}
	return v
}
