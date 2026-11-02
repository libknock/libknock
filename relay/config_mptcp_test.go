package relay

import "testing"

func TestNewGatewayPassesEnableMPTCP(t *testing.T) {
	if NewGateway(Config{}).EnableMPTCP {
		t.Fatal("EnableMPTCP must default to false")
	}
	if !NewGateway(Config{EnableMPTCP: true}).EnableMPTCP {
		t.Fatal("NewGateway dropped EnableMPTCP")
	}
}
