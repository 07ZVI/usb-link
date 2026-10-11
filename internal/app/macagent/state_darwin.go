//go:build darwin

package macagent

import (
	"encoding/json"
	"fmt"
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"
)

func boundedStatus(v string) string {
	r := []rune(v)
	if len(r) > 1024 {
		r = r[:1024]
	}
	return string(r)
}

// The observed old state is 18116 bytes, mostly one failed-command status.
// Accept a bounded legacy status, without relaxing identity or ownership checks.
func decodeState(b []byte) (s State, err error) {
	if len(b) > 65536 {
		return s, fmt.Errorf("oversized state")
	}
	if err = json.Unmarshal(b, &s); err != nil {
		return
	}
	if s.Product != product || len(s.Owned) > 2 || len(s.BinarySHA) != 64 || strings.Trim(s.BinarySHA, "0123456789abcdef") != "" {
		return s, fmt.Errorf("invalid owned helper state")
	}
	if s.AddressProfile != "" && s.AddressProfile != usbaddress.Legacy && s.AddressProfile != usbaddress.Unified {
		return s, fmt.Errorf("unknown address profile")
	}
	s.LastStatus = boundedStatus(s.LastStatus)
	return
}
