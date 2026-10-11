package ipadncm

// Timing observes the existing, current session proofs. UI text, a DHCP ACK,
// old peer flags during recovery and the management listener are not readiness.
func startupNetworkReady(r ApplicationResult) bool {
	if r.WindowsIPv4 != "10.6.9.1" || r.Error != "" || r.DHCPError != "" || r.RuntimePreparationError != "" {
		return false
	}
	switch r.DeviceKind {
	case "Mac":
		return r.Status == "MAC_RUNNING" && r.MacPeerResolved && r.FileReceiverReady && r.FileError == ""
	case "iPad":
		return r.Status == "USB_APPLICATION_TRIAL_RUNNING" && r.DHCPStarted && r.PeerIPv4NeighborVerified
	}
	return false
}

var observeStartupReadiness = func(ApplicationResult) {}
