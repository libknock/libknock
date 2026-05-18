package knock

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/libknock/libknock/auth"
)

const (
	SYNKnockPurpose = "syn-knock"
)

func ValidateSendOptions(opts SendOptions) error {
	if err := ValidateClientSecret(ClientSecret{ClientID: opts.ClientID, Secret: opts.Secret}); err != nil {
		return err
	}
	return validateProtectedPort(opts.ServerPort)
}

func ComputeSYNFields(secret []byte, clientID string, serverPort int, slot int64) SYNFields {
	tag := ComputeSYNTag(secret, clientID, serverPort, slot)
	window := binary.BigEndian.Uint16(tag[4:6])
	if window == 0 {
		window = 1
	}
	return SYNFields{Sequence: binary.BigEndian.Uint32(tag[0:4]), Window: window, Timestamp: binary.BigEndian.Uint32(tag[6:10])}
}

func ComputeSYNTag(secret []byte, clientID string, serverPort int, slot int64) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(SYNKnockPurpose))
	writeString(mac, clientID)
	writeUint16(mac, uint16(serverPort))
	writeInt64(mac, slot)
	return mac.Sum(nil)
}

func VerifySYNFields(fields SYNFields, clients []ClientSecret, serverPort int, now time.Time, window time.Duration) (string, bool) {
	current := SlotFor(now, window)
	for _, client := range clients {
		if ValidateClientSecret(client) != nil {
			continue
		}
		for _, delta := range []int64{-1, 0, 1} {
			if ComputeSYNFields(client.Secret, client.ClientID, serverPort, current+delta) == fields {
				return client.ClientID, true
			}
		}
	}
	return "", false
}

func CheckSYNReplay(cache auth.ReplayCache, clientID string, fields SYNFields, serverPort int) error {
	if cache == nil {
		return nil
	}
	var nonce [14]byte
	binary.BigEndian.PutUint32(nonce[0:4], fields.Sequence)
	binary.BigEndian.PutUint16(nonce[4:6], fields.Window)
	binary.BigEndian.PutUint32(nonce[6:10], fields.Timestamp)
	binary.BigEndian.PutUint16(nonce[10:12], uint16(serverPort))
	binary.BigEndian.PutUint16(nonce[12:14], uint16(len(SYNKnockPurpose)))
	return cache.CheckAndMark(clientID, nonce[:])
}

func validateProtectedPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("protected port must be in 1..65535")
	}
	return nil
}

func SlotFor(t time.Time, window time.Duration) int64 {
	if window <= 0 {
		window = 30 * time.Second
	}
	if window < time.Second {
		window = time.Second
	}
	slotSize := int64(window / time.Second)
	return t.Unix() / slotSize
}
