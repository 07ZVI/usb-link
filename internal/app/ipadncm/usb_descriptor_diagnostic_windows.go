//go:build windows && amd64

package ipadncm

func descriptorRecheckSummary(phase string, before, current Snapshot) USBDescriptorRecheckDiagnostic {
	d := USBDescriptorRecheckDiagnostic{ConnectionReadErrors: current.ConnectionReadErrors, ConnectionNotPresent: current.ConnectionNotPresent, ConnectionReadErrorCodes: current.ConnectionReadErrorCodes, Phase: phase, InventoryError: current.Error, HubsScanned: current.HubsScanned, HubErrors: current.HubErrors, DeviceCount: len(current.Devices), SameRoot: sameRootInstance(before, current), ActiveNCM: HasActiveNCM(current)}
	if len(current.Devices) == 1 {
		x := current.Devices[0]
		d.IdentityVerified = x.USBDescriptorIdentityVerified
		d.ProductReadStatus = x.USBProductReadStatus
		d.SerialReadStatus = x.USBSerialReadStatus
		d.SerialFailureShape = x.USBSerialFailureShape
		d.RejectionCodes = x.Errors
	}
	d.OwnOperationCorrelation = descriptorOwnOperationCorrelation()
	return sanitizeUSBDescriptorRecheck(d)
}
