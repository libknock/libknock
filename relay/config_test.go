package relay

import (
	"reflect"
	"testing"
	"time"

	"github.com/libknock/libknock/auth"
	"github.com/libknock/libknock/firewall"
)

func TestNewGatewayCopiesConfigFields(t *testing.T) {
	cfg := Config{Listen: "127.0.0.1:1", Upstream: "127.0.0.1:2", Auth: auth.ServerConfig{ServerPort: 443}, Firewall: firewall.Noop{}, KnockMethod: "udp", KnockListen: "127.0.0.1:3", KnockPort: 9444, KnockTimeWindow: time.Second, KnockMaxFrameSize: 256, KnockNonceTTL: time.Minute, AllowTTL: 2 * time.Minute, UpstreamConnectTimeout: 3 * time.Second, IdleTimeout: 4 * time.Second, RemoveAfterAuth: true, MaxConnectionsPerKnock: 1, DisableSessionBinding: true, MaxPendingAuth: 7, MaxAuthWorkers: 8}
	got := NewGateway(cfg)
	cfgv := reflect.ValueOf(cfg)
	gv := reflect.ValueOf(*got)
	for i := 0; i < cfgv.NumField(); i++ {
		name := cfgv.Type().Field(i).Name
		gf := gv.FieldByName(name)
		if !gf.IsValid() {
			t.Fatalf("Gateway missing field copied from Config.%s", name)
		}
		if !reflect.DeepEqual(cfgv.Field(i).Interface(), gf.Interface()) {
			t.Fatalf("NewGateway did not copy %s: got %#v want %#v", name, gf.Interface(), cfgv.Field(i).Interface())
		}
	}
}

func TestConfigWithDefaults(t *testing.T) {
	cfg := Config{}.WithDefaults()
	if cfg.Firewall == nil {
		t.Fatal("default firewall is nil")
	}
	if cfg.AllowTTL <= 0 || cfg.UpstreamConnectTimeout <= 0 || cfg.MaxPendingAuth <= 0 || cfg.MaxAuthWorkers <= 0 {
		t.Fatalf("missing defaults: %#v", cfg)
	}
}
