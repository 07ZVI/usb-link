//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"suhang/usbnet/internal/buildinfo"
	"suhang/usbnet/internal/diagnostics/grouptrial"
)

const directNetworkModeStatus = "DIRECT_NCM_READY_FOR_NETWORK_VERIFICATION"

// This marks USB mode readiness only. Connected remains the existing DHCP and
// exact IPv4-peer result, never a started UsbNcm devnode.
func LocalNCMDirectModeReady(r Result) bool {
	return buildinfo.LocalDiagnostics == "true" && r.Status == directNetworkModeStatus && r.USBIdentifiersVerified && r.ReenumerationSeen && r.After != nil && len(r.After.Devices) == 1 && directNetworkTopology(r.After.Devices[0].Configurations, r.After.Devices[0].CurrentConfiguration)
}

func directLiveIntent(s Snapshot) (localNCMDirectJournal, uint64, bool) {
	c := localNCMDirect
	c.mu.Lock()
	rev, dir := c.revision, c.dir
	issued, ctx, issuedRev := c.issued, c.issuedContext, c.issuedRevision
	c.mu.Unlock()
	if !c.allowed(rev) || issuedRev != rev || issued == nil || ctx == nil || ctx != connectionContext() || ctx.Err() != nil || len(s.Devices) != 1 || !directNetworkTopology(s.Devices[0].Configurations, s.Devices[0].CurrentConfiguration) {
		return localNCMDirectJournal{}, rev, false
	}
	j, found, e := readLocalNCMDirectJournal(dir)
	return j, rev, e == nil && found && j.RequestedMode == 5 && sameDirectJournal(*issued, j) && directTargetMatches(j, s)
}

// A saved switch or a journal alone cannot authorize a new process/attempt in
// cfg1. Require this attempt's earlier cfg3 descriptor consent and own SET5.
func localDirectCurrentConsentLayout(a *ConnectionAuthorization, s Snapshot) bool {
	if a == nil || buildinfo.LocalDiagnostics != "true" {
		return false
	}
	_, _, live := directLiveIntent(s)
	if !live {
		return false
	}
	usbConsentMu.Lock()
	ok := a.Once && a.grantedUSB.Valid() && a.descriptorGrantContext == a.guardContext && a.guardContext == connectionContext() && currentUSBDescriptorPermission(a.descriptorGrantContext, a.grantedDescriptor, localDirectDescriptorAttachment(s)) && strings.EqualFold(a.grantedRoot, exactIPadRoot(s))
	usbConsentMu.Unlock()
	return ok
}

func localDirectDescriptorAttachment(s Snapshot) usbDescriptorAttachment {
	if _, _, live := directLiveIntent(s); !live {
		return usbDescriptorAttachment{}
	}
	d := s.Devices[0]
	return usbDescriptorAttachment{root: exactIPadRoot(s), hub: d.hub, port: d.port, serial: d.usbSerial, product: d.USBProduct, verified: d.USBDescriptorIdentityVerified}
}

type directNetworkTarget struct {
	dir, root, driver string
	revision          uint64
	journal           localNCMDirectJournal
	ctx               context.Context
	consent           func() bool
	location          []string
	bcdDevice         uint16
}

func (t *directNetworkTarget) rootID() string    { return t.root }
func (t *directNetworkTarget) driverKey() string { return t.driver }
func (t *directNetworkTarget) allowed() bool {
	return t.ctx.Err() == nil && localNCMDirect.allowed(t.revision)
}
func (t *directNetworkTarget) descriptorProof(s Snapshot) bool {
	return t.allowed() && verifyDirectJournal(t.dir, t.journal) == nil && directTargetMatches(t.journal, s) && s.Devices[0].usbBCDDevice == t.bcdDevice && directNetworkTopology(s.Devices[0].Configurations, s.Devices[0].CurrentConfiguration)
}

func directRootDriver(root, expected string) (string, string) {
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Enum\`+root, registry.QUERY_VALUE)
	if e != nil {
		return "", "DIRECT_ROOT_REGISTRY_UNAVAILABLE"
	}
	defer k.Close()
	d, _, e := k.GetStringValue("Driver")
	if e != nil || !existingGroupingDriverPattern.MatchString(d) || expected != "" && !strings.EqualFold(d, expected) {
		return "", "DIRECT_ROOT_DRIVER_ASSOCIATION_CHANGED"
	}
	s, _, e := k.GetStringValue("Service")
	if e != nil || !strings.EqualFold(s, "usbccgp") {
		return "", "DIRECT_ROOT_SERVICE_UNPROVEN"
	}
	f, _, e := k.GetStringsValue("LowerFilters")
	if e != nil || len(f) != 1 || !strings.EqualFold(f[0], "AppleLowerFilter") {
		return "", "DIRECT_ROOT_FILTERS_UNPROVEN"
	}
	software, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Class\`+d, registry.QUERY_VALUE)
	if e != nil {
		return "", "DIRECT_ROOT_DRIVER_KEY_UNAVAILABLE"
	}
	defer software.Close()
	v, _, e := software.GetStringValue("DriverVersion")
	if e != nil || v != "486.0.0.0" {
		return "", "DIRECT_OFFICIAL_DRIVER_VERSION_UNSUPPORTED"
	}
	return d, ""
}

func directCMProof(s Snapshot, root string, location []string, bcdDevice uint16) (Node, string) {
	if s.Error != "" || len(s.Nodes) != 2 {
		return Node{}, "DIRECT_EXACT_ROOT_AND_ONE_NCM_REQUIRED"
	}
	var child Node
	roots, controls := 0, 0
	for _, n := range s.Nodes {
		belongs, e := configuredStartupNodeScope(n, root)
		if e != "" || !belongs || !nodeCMReadable(n) || !grouptrial.NativeStartObserved(n.Problem, n.StateError, n.DevNodeStatus) || grouptrial.NeedsWindowsRestart(n.DevNodeStatus) {
			return child, "DIRECT_NATIVE_NODE_UNHEALTHY_OR_SCOPE_CHANGED"
		}
		var nativeStatus, nativeProblem uint32
		if windows.CM_Get_DevNode_Status(&nativeStatus, &nativeProblem, n.devInst, 0) != nil || nativeProblem != 0 || nativeStatus&8 == 0 || nativeStatus&0x100 != 0 {
			return child, "DIRECT_NATIVE_NODE_CHANGED"
		}
		if strings.EqualFold(n.instanceID, root) {
			if !strings.EqualFold(n.Service, "usbccgp") || n.DriverVersion != "486.0.0.0" || !sameCachedLocation(location, n.locationPaths) {
				return child, "DIRECT_ROOT_PHYSICAL_OR_DRIVER_CHANGED"
			}
			roots++
		} else {
			binding := directBindingProof(n.IDPrefix, n.Service, n.DriverINF, n.LowerFilters, n.UpperFilters, &bcdDevice)
			localNCMDirect.mu.Lock()
			localNCMDirect.state.Binding = &binding
			localNCMDirect.mu.Unlock()
			if binding.Failure != "" {
				return child, binding.Failure
			}
			if problem := directNCMDriver(n); problem != "" {
				return child, problem
			}
			controls++
			child = n
		}
	}
	if roots != 1 || controls != 1 {
		return child, "DIRECT_EXACT_ROOT_AND_ONE_NCM_REQUIRED"
	}
	return child, ""
}

func directNCMDriver(n Node) (problem string) {
	infEvidence, providerEvidence := "not_sampled", "not_sampled"
	defer func() {
		localNCMDirect.mu.Lock()
		defer localNCMDirect.mu.Unlock()
		if localNCMDirect.state.Binding != nil {
			binding := *localNCMDirect.state.Binding
			binding.NativeResult = problem
			if problem == "" {
				binding.NativeResult = "VERIFIED"
			}
			binding.NativeINF, binding.NativeProvider = infEvidence, providerEvidence
			localNCMDirect.state.Binding = &binding
		}
	}()
	service, e := ipadNativeString(n.devInst, 6)
	if e != nil || !strings.EqualFold(service, "UsbNcm") {
		return "DIRECT_NCM_CURRENT_SERVICE_UNPROVEN"
	}
	driver, e := ipadNativeString(n.devInst, 11)
	if e != nil || !netDriverKeyPattern.MatchString(driver) {
		return "DIRECT_NCM_CURRENT_DRIVER_UNPROVEN"
	}
	k, e := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Class\`+driver, registry.QUERY_VALUE)
	if e != nil {
		return "DIRECT_NCM_DRIVER_REGISTRY_UNAVAILABLE"
	}
	defer k.Close()
	inf, _, e := k.GetStringValue("InfPath")
	infEvidence = directEvidenceINF(inf)
	if e != nil || !strings.EqualFold(inf, "usbncm.inf") {
		return "DIRECT_INBOX_NCM_INF_UNPROVEN"
	}
	provider, _, e := k.GetStringValue("ProviderName")
	providerEvidence = "other"
	if e != nil {
		providerEvidence = "unavailable"
	} else if strings.EqualFold(provider, "Microsoft") || strings.EqualFold(provider, "Microsoft Corporation") {
		providerEvidence = "Microsoft"
	}
	if e != nil || !strings.EqualFold(provider, "Microsoft") && !strings.EqualFold(provider, "Microsoft Corporation") {
		return "DIRECT_INBOX_NCM_PROVIDER_UNPROVEN"
	}
	return ""
}

func (t *directNetworkTarget) mapping(s Snapshot, expected string, readAdapters func() []NetworkAdapter) (NetworkAdapter, string) {
	if !t.allowed() {
		return NetworkAdapter{}, "DIRECT_SELECTION_OR_INTENT_REVOKED"
	}
	if len(s.Devices) > 0 && (!directTargetMatches(t.journal, s) || s.Devices[0].usbBCDDevice != t.bcdDevice || !directNetworkTopology(s.Devices[0].Configurations, s.Devices[0].CurrentConfiguration)) {
		return NetworkAdapter{}, "DIRECT_DESCRIPTOR_TARGET_CHANGED"
	}
	if len(s.Devices) > 0 && (t.consent == nil || !t.consent()) {
		return NetworkAdapter{}, "DIRECT_CURRENT_CONSENT_REQUIRED"
	}
	if _, e := directRootDriver(t.root, t.driver); e != "" {
		return NetworkAdapter{}, e
	}
	n, e := directCMProof(s, t.root, t.location, t.bcdDevice)
	if e != "" {
		return NetworkAdapter{}, e
	}
	as := readAdapters()
	t.networkEvidence(func(d *directNetworkEvidence) {
		d.NICSampled, d.NICCount = true, len(as)
		d.Matched, d.StatisticsRead, d.ReadError = false, false, false
		d.OperStatus, d.MediaState = 0, 0
		d.AdminStatus, d.StatusFlags = 0, 0
		d.InstanceMatched, d.ExpectedMatched = false, false
		if len(as) == 1 {
			a := as[0]
			d.Matched, d.StatisticsRead, d.ReadError = a.Matched, a.StatisticsRead, a.Error != ""
			d.OperStatus, d.MediaState = a.OperStatus, a.MediaConnectState
			d.AdminStatus, d.StatusFlags = a.AdminStatus, a.InterfaceAndOperStatusFlags
			d.InstanceMatched, d.ExpectedMatched = a.instanceID == n.instanceID, expected == "" || a.key == expected
		}
	})
	if len(as) != 1 {
		return NetworkAdapter{}, "DIRECT_UNIQUE_OPERATIONAL_NIC_REQUIRED"
	}
	a := as[0]
	if !a.Matched || !a.StatisticsRead || a.Error != "" || a.OperStatus != 1 || a.MediaConnectState != 1 || a.instanceID != n.instanceID || expected != "" && a.key != expected {
		return NetworkAdapter{}, "DIRECT_UNIQUE_OPERATIONAL_NIC_REQUIRED"
	}
	if _, e = directRootDriver(t.root, t.driver); e != "" {
		return NetworkAdapter{}, e
	}
	if _, e = directCMProof(s, t.root, t.location, t.bcdDevice); e != "" || !t.allowed() {
		return NetworkAdapter{}, "DIRECT_TARGET_CHANGED_DURING_MAPPING"
	}
	return a, ""
}

func (t *directNetworkTarget) networkEvidence(update func(*directNetworkEvidence)) {
	c := localNCMDirect
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.revision != t.revision {
		return
	}
	if c.state.Network == nil {
		c.state.Network = &directNetworkEvidence{PeerStage: "not_started"}
	}
	update(c.state.Network)
}

func (t *directNetworkTarget) runtimeEvidence(r ApplicationResult) {
	c := localNCMDirect
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.revision != t.revision || t.ctx.Err() != nil {
		return
	}
	c.state.NetworkReady = directIPv4Ready(r.DHCPACKs, r.PeerIPv4NeighborVerified, r.Error)
	c.state.Effective = c.state.NetworkReady
	if c.state.NetworkReady {
		c.state.Phase = "direct_ipv4_peer_verified"
	} else {
		c.state.Phase = "direct_network_waiting_for_ipv4_peer"
	}
}

// The backend owns only the normal application network transaction. It never
// invents a grouping original, writes EnumeratorClass or restarts a devnode.
func RunLocalNCMDirectNetwork(version, dir, system string, mode Result, consent func() bool) (r GroupingResult, handled bool) {
	if !strings.HasPrefix(mode.Status, "DIRECT_") {
		return r, false
	}
	handled = true
	r.Transaction = grouptrial.Report{Status: "DIRECT_NETWORK_NO_GROUPING_MUTATION"}
	fail := func(e string) (GroupingResult, bool) {
		r.Transaction.Error = e
		localNCMDirect.mu.Lock()
		localNCMDirect.state.Error = e
		localNCMDirect.state.Phase = "direct_network_incomplete"
		localNCMDirect.mu.Unlock()
		return r, true
	}
	if !LocalNCMDirectModeReady(mode) {
		return fail("DIRECT_MODE_PROOF_REQUIRED")
	}
	s := Inspect()
	r.Before = s
	j, rev, live := directLiveIntent(s)
	if !live || !directTargetMatches(j, mode.Before) || consent == nil || !consent() {
		return fail("DIRECT_CURRENT_IDENTITY_AND_CONSENT_REQUIRED")
	}
	driver, e := directRootDriver(j.Root, "")
	if e != "" {
		return fail(e)
	}
	// Same pinned official Apple stack used for SET5, including the root filter.
	if verifyInstalledAppleControlDriver() != nil {
		return fail("DIRECT_OFFICIAL_CONTROL_DRIVER_CHANGED")
	}
	sys, se := windows.GetSystemDirectory()
	if se != nil {
		return fail("DIRECT_OFFICIAL_ROOT_DRIVER_UNREADABLE")
	}
	data, se := os.ReadFile(filepath.Join(sys, "drivers", "AppleLowerFilter.sys"))
	if se != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != "61c6533dadad5c47bdcf996297e69501092ffb0d1f1dcc2ac6df92e6043d5b43" {
		return fail("DIRECT_OFFICIAL_ROOT_DRIVER_UNPROVEN")
	}
	ctx, cancel := context.WithCancel(connectionContext())
	defer cancel()
	localNCMDirect.mu.Lock()
	if localNCMDirect.revision != rev || !localNCMDirect.master || !localNCMDirect.state.Requested {
		localNCMDirect.mu.Unlock()
		return fail("DIRECT_SELECTION_REVOKED")
	}
	localNCMDirect.sessionCancel = cancel
	localNCMDirect.running = true
	localNCMDirect.state.Busy = true
	localNCMDirect.state.Phase = "direct_native_nic_verifying"
	localNCMDirect.state.Error = ""
	localNCMDirect.mu.Unlock()
	defer func() {
		localNCMDirect.mu.Lock()
		localNCMDirect.sessionCancel = nil
		localNCMDirect.running = false
		localNCMDirect.state.Busy = false
		localNCMDirect.state.Effective = false
		localNCMDirect.state.NetworkReady = false
		localNCMDirect.state.RecoveryRequired = true
		if localNCMDirect.state.Error == "" {
			localNCMDirect.state.Phase = "replug_required"
		}
		localNCMDirect.mu.Unlock()
	}()
	t := &directNetworkTarget{dir: dir, root: j.Root, driver: driver, revision: rev, journal: j, ctx: ctx, consent: consent, bcdDevice: s.Devices[0].usbBCDDevice}
	for _, n := range s.Nodes {
		if strings.EqualFold(n.instanceID, j.Root) {
			t.location = append([]string(nil), n.locationPaths...)
		}
	}
	// Driver initialization can lag descriptor publication. Wait read-only on
	// the same target and cancellation scope, without a retry SET_MODE.
	waitCtx, stopWait := context.WithTimeout(ctx, 10*time.Second)
	defer stopWait()
	for i := 0; i < 10; i++ {
		s = inventory(waitCtx)
		if !t.descriptorProof(s) {
			return fail("DIRECT_DESCRIPTOR_OR_INTENT_CHANGED")
		}
		_, e = t.mapping(s, "", func() []NetworkAdapter { return readNCMAdapters(s) })
		if e == "" {
			break
		}
		if waitCtx.Err() != nil {
			return fail("DIRECT_NETWORK_CANCELLED")
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-waitCtx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	if e != "" {
		return fail(e)
	}
	if !consent() {
		return fail("DIRECT_CURRENT_CONSENT_REQUIRED")
	}
	backendMode := mode
	backendMode.Before = s
	b := &groupingBackend{version: version, dir: dir, system: system, mode: backendMode, result: &r, applicationConsent: consent, directTarget: t, applicationContext: ctx}
	r.NativeStartedNodes = 1
	recordConnectionStage("native_ncm_started", "local_direct_single_ncm_no_grouping_write")
	t.networkEvidence(func(d *directNetworkEvidence) { d.PeerStage = "verifying" })
	peer := b.waitForPeerReady()
	r.PeerProbe = &peer
	t.networkEvidence(func(d *directNetworkEvidence) {
		d.PeerStage, d.PeerStatus = "complete", directEvidenceCode(peer.Status)
		d.NeighborCount, d.NeighborError = len(peer.NeighborsAfter), peer.NeighborError != ""
		d.EchoCount, d.IPv6Verified = len(peer.Echoes), peer.IPv6EchoVerified
		for _, echo := range peer.Echoes {
			if echo.APIParsed {
				d.ParsedEchoes++
			}
			if echo.NoncePayloadMatches {
				d.NonceMatches++
			}
			if echo.ScopedNonceRoundtrip {
				d.ScopedRoundtrips++
			}
		}
	})
	if !peer.IPv6EchoVerified {
		return fail("DIRECT_PEER_VERIFICATION_FAILED_" + peer.Status)
	}
	localNCMDirect.mu.Lock()
	localNCMDirect.state.Phase = "direct_network_session_starting"
	localNCMDirect.mu.Unlock()
	app := b.runApplication(peer)
	r.Application = &app
	if b.applicationRestoreError != "" {
		r.Transaction.RestoreError = b.applicationRestoreError
		return fail(b.applicationRestoreError)
	}
	if app.Error != "" {
		return fail(app.Error)
	}
	return r, true
}
