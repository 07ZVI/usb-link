//go:build windows && amd64

package ipadncm

import (
	"strings"
	"time"
)

func authorizationReadback(before, current Snapshot, elapsed time.Duration) usbAuthorizationReadback {
	d := usbAuthorizationReadback{
		USB:                   descriptorRecheckSummary("USB_AUTHORIZATION_READBACK", before, current),
		ExactRootPresent:      exactIPadRoot(current) != "",
		NetworkLayoutEligible: networkOnlyUSBEligible(current),
	}
	// sameRootInstance requires an eligible layout, so even a cfg0 snapshot
	// compared with itself returns false. Report root identity separately.
	beforeRoot, currentRoot := exactIPadRoot(before), exactIPadRoot(current)
	d.USB.SameRoot = beforeRoot != "" && currentRoot != "" && strings.EqualFold(beforeRoot, currentRoot)
	// descriptorRecheckSummary already bounds each list at sixteen.
	d.ReadCodesOmitted = max(0, len(current.ConnectionReadErrorCodes)-len(d.USB.ConnectionReadErrorCodes))
	d.USB.QueryDurationMS = elapsed.Milliseconds()
	if len(current.Devices) == 1 {
		d.CurrentConfiguration = current.Devices[0].CurrentConfiguration
		d.RejectionCodesOmitted = max(0, len(current.Devices[0].Errors)-len(d.USB.RejectionCodes))
	}
	return d
}
