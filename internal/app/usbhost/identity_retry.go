package usbhost

import (
	"fmt"
	"time"
)

// Retry only the fixed read-only driver query. Native identity/mapping changes
// immediately abort; address ownership and every mutation happen outside this
// helper and are never retried here.
func readRecoveryDriverIdentity(initial hostIdentity, query func() (hostIdentity, bool, error), verify func(uint32) error, wait func(time.Duration)) (int, error) {
	if e := validateHostCandidates([]hostIdentity{initial}); e != nil {
		return 0, e
	}
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			wait(500 * time.Millisecond)
		}
		current, present, e := query()
		if e != nil {
			return attempt - 1, e
		}
		if !present {
			return attempt - 1, fmt.Errorf("USB_HOST_DRIVER_INSTANCE_DISAPPEARED")
		}
		if e = validateHostCandidates([]hostIdentity{current}); e != nil {
			return attempt - 1, e
		}
		if current != initial {
			return attempt - 1, fmt.Errorf("USB_HOST_DRIVER_MAPPING_CHANGED_DURING_READBACK")
		}
		last = verify(initial.Index)
		if last == nil {
			return attempt, nil
		}
	}
	return 3, last
}
