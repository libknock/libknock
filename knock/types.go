package knock

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/libknock/libknock/auth"
)

const MaxFrameSize = DefaultMaxKnockFrameSize
const DefaultSequenceMaxParts = 8

var ErrUnsupported = errors.New("raw knock requires platform raw socket support and privileges")

type ClientSecret struct {
	ClientID string
	Secret   []byte
}

type Event struct {
	SourceIP  net.IP
	ClientID  string
	Nonce     string
	Method    string
	Parts     int
	SessionID []byte
}

type ListenOptions struct {
	Port             int
	KnockPort        int
	Clients          []ClientSecret
	TimeWindow       time.Duration
	MaxFrameSize     int
	RequireSessionID bool
	ReplayCache      auth.ReplayCache
	AllowPacket      func(net.IP) bool
	InvalidPacket    func(net.IP, string)
	Sequence         SequenceOptions
	NonceTTL         time.Duration
}

type SendOptions struct {
	ServerAddr   string
	ClientID     string
	Secret       []byte
	ServerPort   int
	TimeWindow   time.Duration
	MaxFrameSize int
	Sequence     SequenceOptions
	SessionID    []byte
}

type Handler func(Event)

type SequenceOptions struct {
	Length            int
	SlotSeconds       int
	Window            time.Duration
	PacketInterval    time.Duration
	MaxJitter         time.Duration
	MaxInflightPerIP  int
	MaxTotalInflight  int
	AllowLegacySYNSeq bool
}

func ValidateClientSecret(client ClientSecret) error {
	if client.ClientID == "" || len(client.ClientID) > 65535 || strings.Contains(client.ClientID, "\x00") {
		return auth.ErrInvalidClientID
	}
	if len(client.Secret) < auth.MinSecretSize {
		return auth.ErrInvalidSecret
	}
	return nil
}

func ValidateClientSecrets(clients []ClientSecret) error {
	if len(clients) == 0 {
		return auth.ErrMissingSecretResolver
	}
	for _, client := range clients {
		if err := ValidateClientSecret(client); err != nil {
			return err
		}
	}
	return nil
}
