package auth

import "testing"

func TestAcceptsProtocolMatrix(t *testing.T) {
	for _, tc := range []struct {
		name  string
		list  []AuthProtocol
		probe AuthProtocol
		want  bool
	}{
		{"empty-v1", nil, AuthProtocolFrameV1, false},
		{"empty-v2", nil, AuthProtocolEnvelopeV2, false},
		{"v1-v1", []AuthProtocol{AuthProtocolFrameV1}, AuthProtocolFrameV1, true},
		{"v1-v2", []AuthProtocol{AuthProtocolFrameV1}, AuthProtocolEnvelopeV2, false},
		{"v2-v1", []AuthProtocol{AuthProtocolEnvelopeV2}, AuthProtocolFrameV1, false},
		{"both-v1", []AuthProtocol{AuthProtocolFrameV1, AuthProtocolEnvelopeV2}, AuthProtocolFrameV1, true},
		{"both-v2", []AuthProtocol{AuthProtocolFrameV1, AuthProtocolEnvelopeV2}, AuthProtocolEnvelopeV2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := acceptsProtocol(tc.list, tc.probe); got != tc.want {
				t.Fatalf("acceptsProtocol = %v, want %v", got, tc.want)
			}
		})
	}
}
