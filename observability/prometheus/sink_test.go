package prometheus

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/netx"
	"github.com/libknock/libknock/observability"
	prom "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSinkCollectsEvents(t *testing.T) {
	reg := prom.NewRegistry()
	sink, err := New(Config{Registerer: reg, IncludeClientLabel: true, RelayDurationBuckets: []float64{0.1, 1}})
	if err != nil {
		t.Fatal(err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	sink.OnAccept(remote)
	sink.OnAuthOK(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client-a"}, Method: "udp-seq"})
	sink.OnAuthFail(remote, auth.ErrTimeSkew)
	sink.OnAuthDrop(observability.NetxAuthDropEvent{Remote: remote, Reason: netx.ErrAuthBackpressure, Pending: 33})
	sink.OnReplay(remote, 10)
	sink.OnReplayCacheFull(remote, 10, 63, 64)
	sink.OnRateLimited(remote)
	sink.OnKnockOK(observability.KnockEvent{ClientID: "client-a", Method: "udp-seq"})
	sink.OnKnockFail(observability.KnockFailEvent{ClientID: "client-a", Reason: "bad_mac"})
	sink.OnFirewallAllow(observability.FirewallEvent{})
	sink.OnFirewallError(observability.FirewallErrorEvent{})
	sink.OnRelayOK(observability.RelayEvent{ClientID: "client-a", RX: 7, TX: 11, Duration: 200 * time.Millisecond})
	sink.OnRelayError(observability.RelayErrorEvent{ClientID: "client-a", Stage: "upstream"})
	sink.OnRelayError(observability.RelayErrorEvent{ClientID: "client-a", Stage: "pending_full", DroppedCount: 1, Pending: 32})
	if got := testutil.ToFloat64(sink.authAccept); got != 1 {
		t.Fatalf("authAccept = %v", got)
	}
	if got := testutil.ToFloat64(sink.authOK.WithLabelValues("udp-seq", "client-a")); got != 1 {
		t.Fatalf("authOK = %v", got)
	}
	if got := testutil.ToFloat64(sink.authFail.WithLabelValues("time_skew")); got != 1 {
		t.Fatalf("authFail = %v", got)
	}
	if got := testutil.ToFloat64(sink.authFail.WithLabelValues("auth_backpressure")); got != 1 {
		t.Fatalf("authDrop fail label = %v", got)
	}
	if got := testutil.ToFloat64(sink.authReplay); got != 1 {
		t.Fatalf("authReplay = %v", got)
	}
	if got := testutil.ToFloat64(sink.authReplayFull); got != 1 {
		t.Fatalf("authReplayFull = %v", got)
	}
	if got := testutil.ToFloat64(sink.replayCacheLen); got != 63 {
		t.Fatalf("replayCacheLen = %v", got)
	}
	if got := testutil.ToFloat64(sink.replayCacheCap); got != 64 {
		t.Fatalf("replayCacheCap = %v", got)
	}
	if got := testutil.ToFloat64(sink.authRateLimited); got != 1 {
		t.Fatalf("authRateLimited = %v", got)
	}
	if got := testutil.ToFloat64(sink.knockOK.WithLabelValues("udp-seq", "client-a")); got != 1 {
		t.Fatalf("knockOK = %v", got)
	}
	if got := testutil.ToFloat64(sink.knockFail.WithLabelValues("bad_mac", "client-a")); got != 1 {
		t.Fatalf("knockFail = %v", got)
	}
	if got := testutil.ToFloat64(sink.firewallAllow); got != 1 {
		t.Fatalf("firewallAllow = %v", got)
	}
	if got := testutil.ToFloat64(sink.firewallError); got != 1 {
		t.Fatalf("firewallError = %v", got)
	}
	if got := testutil.ToFloat64(sink.relayOK.WithLabelValues("client-a")); got != 1 {
		t.Fatalf("relayOK = %v", got)
	}
	if got := testutil.ToFloat64(sink.relayRX.WithLabelValues("client-a")); got != 7 {
		t.Fatalf("relayRX = %v", got)
	}
	if got := testutil.ToFloat64(sink.relayTX.WithLabelValues("client-a")); got != 11 {
		t.Fatalf("relayTX = %v", got)
	}
	if got := testutil.ToFloat64(sink.relayError.WithLabelValues("upstream", "client-a")); got != 1 {
		t.Fatalf("relayError = %v", got)
	}
	if got := testutil.ToFloat64(sink.relayError.WithLabelValues("pending_full", "client-a")); got != 1 {
		t.Fatalf("relay pending_full error = %v", got)
	}
	if got := testutil.ToFloat64(sink.relayPendingFull); got != 2 {
		t.Fatalf("relayPendingFull = %v", got)
	}
	if got := testutil.ToFloat64(sink.relayDropped); got != 2 {
		t.Fatalf("relayDropped = %v", got)
	}
	if got := testutil.ToFloat64(sink.relayPending); got != 32 {
		t.Fatalf("relayPending = %v", got)
	}
	if _, err := reg.Gather(); err != nil {
		t.Fatal(err)
	}
}

func TestClientLabelIsOptIn(t *testing.T) {
	sink := MustNew(Config{})
	sink.OnAuthOK(auth.PeerInfo{PeerIdentity: auth.PeerIdentity{ClientID: "client-a"}, Method: "udp"})
	if got := testutil.ToFloat64(sink.authOK.WithLabelValues("udp")); got != 1 {
		t.Fatalf("authOK without client label = %v", got)
	}
}

func TestMethodLabelNormalizesUnknownMethods(t *testing.T) {
	sink := MustNew(Config{})
	sink.OnAuthOK(auth.PeerInfo{Method: "client-controlled-method"})
	if got := testutil.ToFloat64(sink.authOK.WithLabelValues("unknown")); got != 1 {
		t.Fatalf("authOK unknown method = %v", got)
	}
}

func TestReasonLabelNormalizesUnknownErrors(t *testing.T) {
	if got := reasonLabel(errors.New("remote detail with high cardinality")); got != "error" {
		t.Fatalf("reason = %q", got)
	}
	if got := reasonLabel(errors.Join(auth.ErrKnockRequired, errors.New("no accepted knock session"))); got != "knock_required" {
		t.Fatalf("joined reason = %q", got)
	}
}

func TestReasonLabelCoversPublicAuthErrors(t *testing.T) {
	tests := map[error]string{
		auth.ErrMissingReplayCache:   "missing_replay_cache",
		auth.ErrServerProofRequired:  "server_proof_required",
		auth.ErrServerProofFailed:    "server_proof_failed",
		auth.ErrUnsupportedFlags:     "unsupported_flags",
		auth.ErrSecretResolverFailed: "secret_resolver_failed",
		auth.ErrTooManyCandidates:    "too_many_candidates",
		auth.ErrHintModeNoneTooBroad: "hint_mode_none_too_broad",
		netx.ErrAuthBackpressure:     "auth_backpressure",
	}
	for err, want := range tests {
		if got := reasonLabel(err); got != want {
			t.Fatalf("reasonLabel(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestLabelsDoNotExposeSensitivePayloadMaterial(t *testing.T) {
	sink := MustNew(Config{IncludeClientLabel: true})
	sink.OnAuthFail(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, errors.New("secret=top sealed_payload=abcdef frame=010203"))
	sink.OnKnockOK(observability.KnockEvent{ClientID: "client-a", Method: "unknown-method-with-user-input"})
	if got := testutil.ToFloat64(sink.authFail.WithLabelValues("error")); got != 1 {
		t.Fatalf("authFail sanitized label = %v", got)
	}
	if got := testutil.ToFloat64(sink.knockOK.WithLabelValues("unknown", "client-a")); got != 1 {
		t.Fatalf("knockOK unknown method label = %v", got)
	}
}

func TestKnownMethodLabelsAreBounded(t *testing.T) {
	for _, method := range []string{"tcp-auth", "tcp-syn", "tcp-syn-seq", "udp", "udp-seq", "udp-passive", "udp-passive-seq"} {
		if got := methodLabel(method); got != method {
			t.Fatalf("methodLabel(%q) = %q", method, got)
		}
	}
	if got := methodLabel(" udp-seq "); got != "udp-seq" {
		t.Fatalf("trimmed method label = %q", got)
	}
}

func TestValidateConfigRejectsInvalidBuckets(t *testing.T) {
	if err := ValidateConfig(Config{RelayDurationBuckets: []float64{0.1, 0.2, 1}}); err != nil {
		t.Fatalf("valid buckets err = %v", err)
	}
	if err := ValidateConfig(Config{RelayDurationBuckets: []float64{0.2, 0.2}}); err == nil {
		t.Fatal("expected non-increasing buckets error")
	}
	if err := ValidateConfig(Config{RelayDurationBuckets: []float64{0}}); err == nil {
		t.Fatal("expected non-positive bucket error")
	}
	if _, err := New(Config{RelayDurationBuckets: []float64{1, 0.5}}); err == nil {
		t.Fatal("New accepted non-increasing buckets")
	}
}

func TestMustNewPanicsOnInvalidBuckets(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected MustNew panic")
		}
	}()
	_ = MustNew(Config{RelayDurationBuckets: []float64{1, 0.5}})
}
