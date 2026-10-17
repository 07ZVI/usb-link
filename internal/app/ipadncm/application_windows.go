//go:build windows && amd64

package ipadncm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/app/usbhost"
	"suhang/usbnet/internal/diagnostics/throughput"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/sharing/fileshare"
	"suhang/usbnet/internal/sharing/usbhttp"
	"suhang/usbnet/internal/transport/ipadsession"
	"suhang/usbnet/internal/transport/usbaddress"
	"sync"
	"time"
)

func (s *applicationState) runDHCP(ctx context.Context, c *net.UDPConn, p ipadsession.Plan, mac [6]byte, guard func() (NetworkAdapter, string), cancel context.CancelFunc) {
	buf, oob := make([]byte, 2048), make([]byte, 256)
	replies := 0
	replyWindow := time.Now()
	for ctx.Err() == nil {
		c.SetReadDeadline(time.Now().Add(time.Second))
		n, on, flags, addr, e := c.ReadMsgUDP(buf, oob)
		if e != nil {
			if ctx.Err() != nil {
				return
			}
			if nerr, ok := e.(net.Error); ok && nerr.Timeout() {
				continue
			}
			s.update(func(r *ApplicationResult) { r.DHCPError = "DHCP_RECEIVE_FAILED" })
			cancel()
			return
		}
		// Interface ancillary identity is checked BEFORE inspecting DHCP payload.
		idx, ok := ipadsession.PacketInterface(oob[:on])
		if !ok || idx != p.Index || addr.Port != 68 || flags&(windows.MSG_TRUNC|windows.MSG_CTRUNC|0x8000) != 0 {
			continue
		}
		req, e := ipadsession.ParseDHCP(buf[:n], mac)
		if e != nil {
			continue
		}
		ipadNetDebug.event("dhcp_rx", fmt.Sprintf("%s ci=%s requested=%s server=%s", dhcpKindName(req.Kind), ipv4Text(req.CI), ipv4Text(req.Requested), ipv4Text(req.Server)))
		if _, err := guard(); err != "" {
			s.update(func(r *ApplicationResult) { r.DHCPError = err })
			cancel()
			return
		}
		switch req.Kind {
		case 1:
			recordUnpairedExperimentEvent("dhcp_discover")
		case 3:
			recordUnpairedExperimentEvent("dhcp_request")
		case 4:
			recordUnpairedExperimentEvent("dhcp_decline")
		default:
			recordUnpairedExperimentEvent("dhcp_other")
		}
		if req.Kind == 4 && req.HasRequested && req.Requested == v4Array(p.PeerIP()) && (!req.HasServer || req.Server == v4Array(p.LocalAddress())) {
			s.update(func(r *ApplicationResult) { r.DHCPDeclined = true; r.DHCPError = "IPAD_DECLINED_OFFERED_ADDRESS_STOP" })
			cancel()
			return
		}
		b, kind := ipadsession.DHCPReplyForPlan(req, p, s.Router)
		if b == nil {
			ipadNetDebug.event("dhcp_no_reply", dhcpKindName(req.Kind))
			continue
		}
		if time.Since(replyWindow) >= time.Minute {
			replies = 0
			replyWindow = time.Now()
		}
		if replies >= 128 {
			s.update(func(r *ApplicationResult) { r.DHCPError = "DHCP_REPLY_LIMIT_STOP" })
			cancel()
			return
		}
		replies++
		c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if e = sendDHCP(c, b, p, req.CI == v4Array(p.PeerIP())); e != nil {
			ipadNetDebug.event("dhcp_tx_failed", fmt.Sprintf("%s unicast=%v error=%v", dhcpKindName(kind), req.CI == v4Array(p.PeerIP()), e))
			s.update(func(r *ApplicationResult) { r.DHCPError = "DHCP_TARGET_SEND_FAILED" })
			cancel()
			return
		}
		ipadNetDebug.event("dhcp_tx", fmt.Sprintf("%s unicast=%v", dhcpKindName(kind), req.CI == v4Array(p.PeerIP())))
		s.update(func(r *ApplicationResult) {
			if req.Kind == 1 {
				r.DHCPDiscoveries++
			}
			if kind == 2 {
				r.DHCPOffers++
			}
			if kind == 5 {
				r.DHCPACKs++
				recordUnpairedExperimentEvent("dhcp_ack_sent")
				recordConnectionStage("dhcp_ack_sent", "targeted_dhcp_reply_sent_not_address_application_proof")
			}
		})
	}
}
func v4Array(ip string) (a [4]byte) { copy(a[:], parseV4(ip)); return }
func sunshineServerInfo(address string) bool {
	client := http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	response, e := client.Get("http://" + net.JoinHostPort(address, "47989") + "/serverinfo")
	if e != nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return false
	}
	b, e := io.ReadAll(io.LimitReader(response.Body, 32769))
	if e != nil || len(b) > 32768 {
		return false
	}
	var v struct {
		XMLName xml.Name `xml:"root"`
		Status  string   `xml:"status_code,attr"`
		Version string   `xml:"appversion"`
		ID      string   `xml:"uniqueid"`
	}
	return xml.Unmarshal(b, &v) == nil && v.Status == "200" && v.Version != "" && len(v.Version) < 128 && v.ID != "" && len(v.ID) < 128
}

func (b *groupingBackend) runApplication(peer PeerProbe) (out ApplicationResult) {
	out.DeviceKind = "iPad"
	out.Status = "APPLICATION_TRIAL_DECLINED_OR_NOT_ELIGIBLE"
	if !peer.IPv6EchoVerified || b.applicationConsent == nil {
		return
	}
	out.Consent = b.applicationConsent()
	if !out.Consent {
		return
	}
	s := connectionMonitor()
	shared := s != nil
	if !shared {
		s = &applicationState{Settings: ShowConnectionSettings}
	}
	s.Lock()
	out.DeviceAuthorization = s.r.DeviceAuthorization
	out.PairedTLSAuthenticated = s.r.PairedTLSAuthenticated
	s.r = out
	// 0.8.128: no default route over USB. The iPad reaches 10.6.9.1 through the
	// RFC3442 host route; a USB default route sends all iPad Internet traffic
	// to a Windows endpoint that drops it.
	s.Router = false
	_ = connectionPreferences().IndependentUSB
	s.Unlock()
	defer func() { out = s.snapshot() }()
	ctx, cancel := context.WithCancel(connectionContext())
	defer cancel()
	s.update(func(r *ApplicationResult) {
		r.Status = "APPLICATION_PREPARING"
		r.RemainingSeconds = -1
		r.RouterAdvertised = s.Router
	})
	if !shared {
		closeUI, uiError := startApplicationUI(ctx, s, cancel)
		if uiError != "" {
			s.update(func(r *ApplicationResult) { r.Error = uiError })
			return
		}
		defer closeUI()
	}
	s.update(func(r *ApplicationResult) { r.WindowOpened = true })
	s.update(func(r *ApplicationResult) {
		for _, e := range peer.Echoes {
			if !e.ScopedNonceRoundtrip || !e.TargetStableAfter || e.Destination != e.ReplyIP {
				continue
			}
			if r.EchoSamples == 0 {
				r.EchoMinMilliseconds = e.RTTMilliseconds
				r.EchoMaxMilliseconds = e.RTTMilliseconds
			} else {
				r.EchoMinMilliseconds = min(r.EchoMinMilliseconds, e.RTTMilliseconds)
				r.EchoMaxMilliseconds = max(r.EchoMaxMilliseconds, e.RTTMilliseconds)
			}
			r.EchoSamples++
		}
	})

	speed, speedError := applicationUSBSpeed(ctx, Inspect())
	s.update(func(r *ApplicationResult) { r.USBSpeed = speed; r.USBSpeedError = speedError })
	a, err := b.currentPeerAdapter(peer.adapterKey)
	if err != "" {
		s.update(func(r *ApplicationResult) { r.Error = err })
		return
	}
	if peer.adapterKey == "" || !probeSourcePresent(a, net.ParseIP(peer.sourceIPv6), peer.ipv6Scope) {
		s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_ADAPTER_CHANGED_DURING_CONSENT" })
		return
	}
	recordConnectionStage("adapter_mapped", "exact_current_peer_adapter_and_ipv6_source_verified")
	var v6 net.IP
	for _, e := range peer.Echoes {
		if e.ScopedNonceRoundtrip && e.TargetStableAfter {
			v6 = net.ParseIP(e.ReplyIP)
			break
		}
	}
	mac, err := targetPeerMAC(a, v6)
	if err != "" {
		s.update(func(r *ApplicationResult) { r.Error = err })
		return
	}
	var raw [12]byte
	if _, e := rand.Read(raw[:]); e != nil {
		s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_TOKEN_UNAVAILABLE" })
		return
	}
	token := hex.EncodeToString(raw[:])
	guid := strings.SplitN(a.key, "/", 2)[0]
	// Host preparation may need this same topology lock. Join before acquiring
	// it, after device mode/driver work and before any network/WFP mutation.
	if err := joinPreparedSharedHost(); err != nil {
		s.update(func(r *ApplicationResult) { r.Error = err.Error() })
		return
	}
	releaseTopology, topologyError := usbaddress.ConfigurationLock(ctx)
	if topologyError != nil {
		s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_TOPOLOGY_CONFIGURATION_BUSY" })
		return
	}
	defer releaseTopology()
	gateway, e := gatewayManager()
	if e != nil {
		s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_GATEWAY_UNAVAILABLE" })
		return
	}
	proofs, e := gateway.OwnedInterfaces()
	if e != nil {
		s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_TOPOLOGY_UNAVAILABLE" })
		return
	}
	host, sharedHost := usbhost.Proof()
	if SimplifiedIPadNetworkConfigured() && !sharedHost {
		s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_SHARED_HOST_UNAVAILABLE" })
		return
	}
	if sharedHost {
		proofs = append(proofs, host)
		e = usbaddress.VerifyProofs(proofs)
	}
	if e != nil {
		s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_HOST_PROOF_CHANGED" })
		return
	}
	server := ""
	if sharedHost && (IPadCandidateFeatures().NativeConflict || netconfig.NativeNetworkEnabled()) {
		// Native read-only verification preserves all route/address and exact
		// interface proof gates without starting a PowerShell process.
		if e := usbaddress.VerifyNoForeignSubnet(a.InterfaceIndex, guid, proofs); e != nil {
			s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_SAFE_SUBNET_UNAVAILABLE" })
			return
		}
		server = "10.6.9.1"
	} else {
		if netconfig.NativeNetworkEnabled() {
			s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_NATIVE_SHARED_HOST_REQUIRED" })
			return
		}
		script, e := usbaddress.ConflictScript(a.InterfaceIndex, guid, proofs)
		if !sharedHost {
			script, e = ipadsession.ConcurrentSubnetScript(a.InterfaceIndex, guid, 1)
		}
		if e != nil {
			s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_SUBNET_PLAN_INVALID" })
			return
		}
		if sharedHost {
			script += "Write-Output '10.6.9.1';"
		}
		text, err := runApplicationScript(b.system, script)
		server = ipadsession.ParseChosenSubnet(text)
		if err != "" || server == "" {
			s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_SAFE_SUBNET_UNAVAILABLE" })
			return
		}
	}
	var ft windows.Filetime
	windows.GetSystemTimeAsFileTime(&ft)
	plan := ipadsession.Plan{Version: 3, GUID: guid, LUID: a.luid, Index: a.InterfaceIndex, ServerIP: server, Token: token, PlannedAt: int64(uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime))}
	if sharedHost {
		plan.Version = 5
		flags, flagError := readUSBHostFlags(plan.LUID)
		if flagError != nil {
			s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_HOST_FLAGS_UNAVAILABLE" })
			return
		}
		plan.HostFlags = flags
	}
	key := a.key
	preflight := func() (NetworkAdapter, string) {
		fresh, er := b.currentPeerAdapter(key)
		if er != "" {
			return fresh, er
		}
		m, er := targetPeerMAC(fresh, v6)
		if er != "" || m != mac {
			return fresh, "APPLICATION_VERIFIED_PEER_CHANGED"
		}
		return fresh, ""
	}
	configuration, configuredPlan, configurationError := b.prepareIPadConfiguration(ctx, a, plan, preflight)
	if configurationError != nil {
		s.update(func(r *ApplicationResult) { r.Error = configurationError.Error() })
		return
	}
	plan = configuredPlan
	j := applicationJournal{Root: b.networkRoot(), Driver: b.networkDriver(), Plan: plan, ResidentFirewall: netconfig.ResidentFirewallEnabled()}
	var gateStop func() error
	if ctx.Err() != nil {
		return
	}
	if err = saveApplicationJournal(b.dir, j, false); err != "" {
		if configuration != nil && configuration.binding.State == "pending" {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
			owner := func() error { return verifyIPadPersistentNative(cleanupCtx, configuration.binding) }
			if ce := interfaceconfig.FinishIPadFailedIntent(cleanupCtx, b.dir, configuration.binding, owner); ce != nil {
				err = "IPAD_CONFIGURATION_INTENT_RETAINED"
			}
			cleanupCancel()
		}
		s.update(func(r *ApplicationResult) { r.Error = err })
		return
	}
	// All subsequent failures must remove owned rules/address, retaining the
	// protected journal when any cleanup is unconfirmed. Group rollback follows.
	defer func() {
		cancel()
		s.update(func(r *ApplicationResult) { r.Status = "APPLICATION_TRIAL_ENDED_RESTORING" })
		recovery := RecoverApplicationSession(b.dir, b.system)
		s.update(func(r *ApplicationResult) { r.Recovery = recovery })
		if recovery.Error != "" {
			b.applicationRestoreError = recovery.Error
		} else if gateStop != nil {
			if e := gateStop(); e != nil {
				b.applicationRestoreError = "USB_GATEWAY_CLEANUP_FAILED: " + e.Error()
				s.update(func(r *ApplicationResult) {
					r.Error = b.applicationRestoreError
					r.Recovery.Error = b.applicationRestoreError
				})
			}
		}
	}()
	if _, err = preflight(); err != "" {
		s.update(func(r *ApplicationResult) { r.Error = err })
		return
	}
	if ctx.Err() != nil {
		return
	}
	var gateErr error
	gateStop, gateErr = attachUSBApplicationGate(a.luid)
	if gateErr != nil {
		s.update(func(r *ApplicationResult) { r.Error = "USB_GATEWAY_PREPARATION_FAILED: " + gateErr.Error() })
		return
	}
	if err = setUSBHostFlags(plan, false); err != "" {
		s.update(func(r *ApplicationResult) { r.Error = err })
		return
	}
	if configurationError = configuration.beforeAddress(ctx); configurationError != nil {
		s.update(func(r *ApplicationResult) { r.Error = configurationError.Error() })
		return
	}
	if e := b.applyOwnedIPadDAD(ctx, a, plan, preflight); e != nil {
		s.update(func(r *ApplicationResult) { r.Error = e.Error() })
		return
	}
	stamp := plan.CreatedAt
	if configuration == nil || configuration.retained == nil {
		stamp, err = createApplicationAddress(plan)
		if err != "" {
			s.update(func(r *ApplicationResult) { r.Error = err })
			return
		}
		plan.CreatedAt = stamp
		j.Plan = plan
		if err = saveApplicationJournal(b.dir, j, true); err != "" {
			s.update(func(r *ApplicationResult) { r.Error = err })
			return
		}
		if configuration != nil {
			plan, configurationError = configuration.afterAddress(ctx, plan)
			if configurationError != nil {
				s.update(func(r *ApplicationResult) { r.Error = configurationError.Error() })
				return
			}
			j.Plan = plan
			if err = saveApplicationJournal(b.dir, j, true); err != "" {
				s.update(func(r *ApplicationResult) { r.Error = err })
				return
			}
		}
	}
	if err = createPeerRoute(plan); err != "" {
		s.update(func(r *ApplicationResult) { r.Error = err })
		return
	}
	releaseTopology()
	stopDescriptorWatch, descriptorWatchProblem := watchUSBDescriptorAttachment(ctx, b.mode.Before, func() {
		s.update(func(r *ApplicationResult) { r.Error = "USB_SERIAL_PRODUCT_OR_ATTACHMENT_CHANGED_OR_UNREADABLE" })
		cancel()
	})
	if descriptorWatchProblem != "" {
		s.update(func(r *ApplicationResult) { r.Error = descriptorWatchProblem })
		return
	}
	defer stopDescriptorWatch()
	guard := func() (NetworkAdapter, string) {
		fresh, er := b.currentActivePeerAdapter(key)
		if er != "" {
			return fresh, er
		}
		if sharedHost && SimplifiedIPadNetworkConfigured() {
			currentHost, valid := usbhost.Proof()
			if !valid || currentHost != host {
				return fresh, "APPLICATION_SHARED_HOST_PROOF_CHANGED"
			}
		}
		if routeError := verifyPeerRoute(plan); routeError != "" {
			return fresh, routeError
		}
		row := addressRow(plan)
		if windows.GetUnicastIpAddressEntry(&row) != nil || row.DadState != 4 || row.InterfaceLuid != plan.LUID || addressStamp(row) != stamp || (plan.Version == 6 && (row.SkipAsSource != 1 || !ipadsession.OwnedAddress(plan, ipadsession.AddressIdentity{LUID: row.InterfaceLuid, Index: row.InterfaceIndex, Prefix: uint32(row.OnLinkPrefixLength), PrefixOrigin: uint32(row.PrefixOrigin), SuffixOrigin: uint32(row.SuffixOrigin), ValidLifetime: row.ValidLifetime, PreferredLifetime: row.PreferredLifetime, CreatedAt: addressStamp(row)}))) {
			return fresh, "APPLICATION_TEMPORARY_ADDRESS_CHANGED"
		}
		return fresh, ""
	}
	if _, err = guard(); err != "" {
		s.update(func(r *ApplicationResult) { r.Error = err })
		return
	}
	if ctx.Err() != nil {
		return
	}
	s.update(func(r *ApplicationResult) {
		r.WindowsIPv4 = plan.ServerIP
		r.ProposedIPadIPv4 = plan.PeerIP()
		if SimplifiedIPadNetworkConfigured() {
			networkOnly.Lock()
			networkOnly.notice = "iPad 詢問信任時請選不信任。Moonlight 請使用目前已核對的 USB 地址 " + plan.ServerIP + "。"
			networkOnly.Unlock()
		}
		recordConnectionStage("ip_configured", "owned_address_and_peer_route_guard_passed")
		r.WindowsIPv6 = peer.sourceIPv6
	})
	script, e := plan.FirewallSetup()
	if e != nil {
		s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_RULE_PLAN_INVALID" })
		return
	}
	if netconfig.ResidentFirewallEnabled() {
		permissionDone := RecordConnectionOperation("application_resident_permission_batch")
		residentErr := b.prepareResidentIPadPermissions(ctx, plan, sharedHost, guard)
		permissionDone()
		if residentErr != nil {
			s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_RESIDENT_PERMISSION_FAILED: " + residentErr.Error() })
			return
		}
	} else if netconfig.NativeNetworkEnabled() {
		firewallDone := RecordConnectionOperation("application_firewall_native")
		nativeErr := netconfig.EnsureIPadSessionRulesNative(ctx, plan, nil)
		firewallDone()
		if nativeErr != nil {
			s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_NATIVE_FIREWALL_SETUP_FAILED: " + nativeErr.Error() })
			return
		}
		if _, problem := guard(); problem != "" {
			s.update(func(r *ApplicationResult) { r.Error = problem })
			return
		}
		exe, nativeErr := os.Executable()
		if nativeErr == nil {
			nativeErr = connectioninstall.Verify(exe)
		}
		if nativeErr != nil {
			s.update(func(r *ApplicationResult) { r.Error = "USB_CORE_EXECUTABLE_UNVERIFIED" })
			return
		}
		coreDone := RecordConnectionOperation("core_permissions_native")
		if sharedHost {
			nativeErr = netconfig.EnsureIPadCoreServicesNative(ctx, usbaddress.InterfaceProof{Index: plan.Index, GUID: plan.GUID, LUID: plan.LUID}, plan.PeerIP(), exe, nil)
		}
		coreDone()
		if nativeErr != nil {
			s.update(func(r *ApplicationResult) { r.Error = "USB_NATIVE_CORE_PERMISSION_FAILED: " + nativeErr.Error() })
			return
		}
	} else if IPadCandidateFeatures().EarlyDHCP || netconfig.CombinedLegacyNetworkEnabled() {
		// Execute the same ordered, scoped scripts in one bounded process. Neither
		// a partial marker nor an error admits DHCP; journals still own cleanup.
		permissionDone := RecordConnectionOperation("application_permission_batch")
		coreScript, coreProblem := applicationCorePermissionScript(plan, sharedHost)
		if coreProblem != "" {
			permissionDone()
			s.update(func(r *ApplicationResult) { r.Error = coreProblem })
			return
		}
		var permissionOutput, permissionProblem string
		if netconfig.CombinedLegacyNetworkEnabled() {
			pin, pinErr := connectioninstall.PinCoreSourceBatchSelf()
			if pinErr != nil {
				permissionProblem = "USB_CORE_EXECUTABLE_UNVERIFIED"
			} else {
				owner := func() error {
					if _, problem := guard(); problem != "" {
						return fmt.Errorf("%s", problem)
					}
					return pin.Refresh()
				}
				batchErr := netconfig.ExecuteCombinedLegacyNetwork(ctx, script+"\n"+coreScript, owner, func(c context.Context, script string) error {
					permissionOutput, permissionProblem = runApplicationPermissionContext(c, b.system, script)
					if permissionProblem != "" || !applicationPermissionBatchReady(permissionOutput) {
						return fmt.Errorf("APPLICATION_PERMISSION_BATCH_FAILED")
					}
					return nil
				})
				if batchErr == nil {
					batchErr = pin.Complete()
				}
				pin.Close()
				if batchErr != nil {
					permissionProblem = "APPLICATION_PERMISSION_BATCH_FAILED"
				}
			}
		} else {
			permissionOutput, permissionProblem = runApplicationPermissionScript(b.system, script+"\n"+coreScript)
		}
		permissionDone()
		if permissionProblem != "" || !applicationPermissionBatchReady(permissionOutput) {
			s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_PERMISSION_BATCH_FAILED" })
			return
		}
	} else {
		firewallDone := RecordConnectionOperation("application_firewall")
		text, problem := runApplicationPermissionScript(b.system, script)
		firewallDone()
		if problem != "" || text != "OWNED_FIREWALL_READY" {
			s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_FIREWALL_SETUP_FAILED" })
			return
		}
		if ctx.Err() != nil {
			return
		}
		coreDone := RecordConnectionOperation("core_permissions")
		coreScript, coreProblem := applicationCorePermissionScript(plan, sharedHost)
		if coreProblem != "" {
			coreDone()
			s.update(func(r *ApplicationResult) { r.Error = coreProblem })
			return
		}
		coreOutput, coreProblem := runApplicationPermissionScript(b.system, coreScript)
		coreDone()
		if coreProblem != "" || coreOutput != "USB_CORE_PERMISSION_READY" {
			s.update(func(r *ApplicationResult) { r.Error = "USB_CORE_PERMISSION_FAILED" })
			return
		}
	}
	if ctx.Err() != nil {
		return
	}
	dhcp, err := dhcpSocket(plan.Index)
	if err != "" {
		s.update(func(r *ApplicationResult) { r.Error = err })
		return
	}
	var wg sync.WaitGroup
	startDHCP := func() {
		wg.Add(1)
		go func() { defer wg.Done(); s.runDHCP(ctx, dhcp, plan, mac, guard, cancel) }()
		recordConnectionStage("dhcp_listener_started", "exact_interface_socket_and_core_permissions_ready")
	}
	// Core permission, exact interface proof, and peer MAC guard are ready.
	// Optional browser/share setup should not delay the first guarded ACK.
	if IPadCandidateFeatures().EarlyDHCP {
		startDHCP()
		s.update(func(r *ApplicationResult) { r.DHCPStarted = true })
	}
	defer func() { cancel(); dhcp.Close(); wg.Wait() }()
	var secret [12]byte
	if _, e = rand.Read(secret[:]); e != nil {
		s.update(func(r *ApplicationResult) { r.Error = "APPLICATION_PROOF_TOKEN_UNAVAILABLE" })
		return
	}
	proofToken := hex.EncodeToString(secret[:])
	speedTest, speedTestErr := throughput.NewBrowser(ctx, plan.PeerIP(), peerAddrString(plan), func() bool { return ctx.Err() == nil }, func(v throughput.Report) { s.update(func(r *ApplicationResult) { r.Benchmark = v }) })
	if speedTestErr != nil {
		s.update(func(r *ApplicationResult) { r.Error = "USB_TEST_PREPARATION_FAILED" })
		return
	}
	defer speedTest.Close()
	throughput.SetDeviceCurrent("iPad", speedTest)

	var shareServer *fileshare.Server
	if catalog, shareErr := connectioninstall.ShareCatalog(); shareErr == nil {
		shareServer, _ = fileshare.NewMulti(catalog, plan.PeerIP(), &fileshare.USB, func() bool { return ctx.Err() == nil })
	}
	s.update(func(r *ApplicationResult) { r.ShareReady = shareServer != nil })
	defer func() {
		s.update(func(r *ApplicationResult) { r.ShareReady = false })
		if shareServer != nil {
			shareServer.Close()
		}
	}()
	usbHandler := http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		host, _, e := net.SplitHostPort(q.RemoteAddr)
		if e != nil || host != plan.PeerIP() {
			http.Error(w, "Not the USB peer", 403)
			return
		}
		fresh, er := guard()
		if er != "" {
			http.Error(w, "USB changed", 503)
			cancel()
			return
		}
		current, er := targetPeerMAC(fresh, net.ParseIP(plan.PeerIP()))
		if er != "" || current != mac {
			http.Error(w, "Peer identity not verified", 403)
			return
		}
		if strings.HasPrefix(q.URL.Path, "/speed/") {
			speedTest.ServeHTTP(w, q)
			return
		}
		if q.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch q.URL.Path {
		case "/":
			fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>USB Link</title><h1>已透過 USB 連到 Windows</h1><p>這只是網頁通信檢查，尚不代表串流已通過。</p><script>fetch('/proof/%s',{cache:'no-store'})</script>", proofToken)
		case "/proof/" + proofToken:
			if _, e = io.WriteString(w, "USB response acknowledged"); e == nil {
				s.update(func(r *ApplicationResult) { r.HTTPVerified = true })
			}
		default:
			http.NotFound(w, q)
		}
	})
	var smbHandler func(context.Context, net.Conn)
	if shareServer != nil {
		smbHandler = func(ctx context.Context, conn net.Conn) {
			fresh, er := guard()
			if er != "" {
				return
			}
			current, er := targetPeerMAC(fresh, net.ParseIP(plan.PeerIP()))
			if er != "" || current != mac {
				return
			}
			shareServer.ServeSMB(ctx, conn)
		}
	}
	stopHTTP, e := usbhttp.RegisterWithBinary(ctx, peerAddrString(plan), plan.PeerIP(), usbHandler, smbHandler)
	if e != nil {
		s.update(func(r *ApplicationResult) { r.Error = "USB_HTTP_LISTENER_UNAVAILABLE" })
		return
	}
	defer stopHTTP()
	if !IPadCandidateFeatures().EarlyDHCP {
		startDHCP()
	}
	s.update(func(r *ApplicationResult) {
		r.Status = "USB_APPLICATION_TRIAL_RUNNING"
		r.WindowsIPv4 = plan.ServerIP
		r.ProposedIPadIPv4 = plan.PeerIP()
		r.DHCPStarted = true
		r.BenchmarkURL = "http://" + peerAddrString(plan) + "/speed/"
		r.ActiveChecksCacheOnly = true
		r.MTU = a.MTU
		r.RemainingSeconds = -1

	})
	recordConnectionStage("optional_application_services_ready", "bounded_usb_http_and_optional_share_registered")
	sunshineProbeDone := RecordConnectionOperation("sunshine_local_probe")
	localOK, usbLocalOK := sunshineServerInfo("127.0.0.1"), sunshineServerInfo(plan.ServerIP)
	sunshineProbeDone()
	s.update(func(r *ApplicationResult) { r.SunshineLoopbackHTTP, r.SunshineUSBLocalHTTP = localOK, usbLocalOK })
	var mdnsStop func() string
	if s.snapshot().SunshineUSBLocalHTTP {
		mdnsStop, err = registerApplicationMDNS(plan.Index, plan.ServerIP, plan.Token)
		s.update(func(r *ApplicationResult) { r.MDNSRegistered = err == ""; r.MDNSError = err })
	}
	defer func() {
		if mdnsStop != nil {
			er := mdnsStop()
			s.update(func(r *ApplicationResult) { r.MDNSCleanupError = er })
		}
	}()
	start := time.Now()
	previous, baselineError := guard()
	if baselineError != "" {
		s.update(func(r *ApplicationResult) { r.Error = baselineError })
		return
	}
	prevTime := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	loops := 0
	debugPeer := net.ParseIP(plan.PeerIP())
	debugIndex := previous.InterfaceIndex
	ipadNetDebug.event("session_monitor_start", fmt.Sprintf("index=%d peer=%s server=%s", debugIndex, plan.PeerIP(), plan.ServerIP))
	ipadNetDebug.store(collectNetDebug("session_monitor_start", debugIndex), true)
	debugVerified, debugOper, debugMedia := false, previous.OperStatus, previous.MediaConnectState
	pinned, pinnedIndex, pinnedLUID := false, uint32(0), uint64(0)
	defer func() {
		if pinned {
			unpinIPadNeighbor(pinnedIndex, pinnedLUID, debugPeer, mac)
			ipadNetDebug.event("peer_neighbor_unpinned", "")
		}
	}()
	defer func() {
		ipadNetDebug.event("session_monitor_end", s.snapshot().Error)
		ipadNetDebug.store(collectNetDebug("session_monitor_end", debugIndex), true)
	}()
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			continue
		case <-ticker.C:
		}
		queryStart := time.Now()
		fresh, er := guard()
		queryEnd := time.Now()
		if er != "" {
			s.update(func(r *ApplicationResult) { r.Error = er })
			cancel()
			break
		}
		elapsed := time.Since(start)
		dt := queryEnd.Sub(prevTime).Seconds()
		faults, faultsValid := (ipadsession.InterfaceFaults{InErrors: fresh.InErrors, OutErrors: fresh.OutErrors, InDiscards: fresh.InDiscards, OutDiscards: fresh.OutDiscards}).Delta(ipadsession.InterfaceFaults{InErrors: previous.InErrors, OutErrors: previous.OutErrors, InDiscards: previous.InDiscards, OutDiscards: previous.OutDiscards})
		s.update(func(r *ApplicationResult) {
			r.ElapsedSeconds = int64(elapsed.Seconds())
			r.RemainingSeconds = -1
			r.Traffic.Add(previous.InOctets, previous.OutOctets, fresh.InOctets, fresh.OutOctets, dt)
			r.Performance.Record(ipadsession.PerformanceSample{RecordedUTC: queryEnd.UTC().Format(time.RFC3339Nano), ElapsedMS: elapsed.Milliseconds(), IntervalMS: dt * 1000, QueryMS: float64(queryEnd.Sub(queryStart)) / float64(time.Millisecond), ReceiveMbps: r.Traffic.ReceiveMbps, TransmitMbps: r.Traffic.TransmitMbps, FaultDeltaValid: faultsValid, Faults: faults})
			r.MTU = fresh.MTU
			r.ObservedReceiveMbps, r.ObservedTransmitMbps = r.Traffic.ReceiveMbps, r.Traffic.TransmitMbps
			r.ReportedTransmitBPS, r.ReportedReceiveBPS = fresh.ReportedTransmitBPS, fresh.ReportedReceiveBPS

		})
		previous = fresh
		prevTime = queryEnd
		loops++
		if loops%300 == 0 {
			if err := refreshPeerRoute(plan); err != "" {
				s.update(func(r *ApplicationResult) { r.Error = err })
				cancel()
				break
			}
			if err := refreshApplicationAddress(plan); err != "" {
				s.update(func(r *ApplicationResult) { r.Error = err })
				cancel()
				break
			}
		}
		v4MAC, macError := targetPeerMAC(fresh, net.ParseIP(plan.PeerIP()))
		v4Peer := macError == "" && v4MAC == mac
		if fresh.OperStatus != debugOper || fresh.MediaConnectState != debugMedia {
			ipadNetDebug.event("interface_status", fmt.Sprintf("oper %s -> %s, media %s -> %s", operStatusName(debugOper), operStatusName(fresh.OperStatus), mediaConnectName(debugMedia), mediaConnectName(fresh.MediaConnectState)))
			debugOper, debugMedia = fresh.OperStatus, fresh.MediaConnectState
		}
		peerState := peerNeighborState(debugIndex, debugPeer)
		if v4Peer && peerState != "permanent" {
			if e := pinIPadNeighbor(fresh.InterfaceIndex, fresh.luid, debugPeer, mac); e != nil {
				ipadNetDebug.event("peer_neighbor_pin_failed", e.Error())
			} else {
				ipadNetDebug.event("peer_neighbor_pinned", fmt.Sprintf("index=%d was=%s", fresh.InterfaceIndex, peerState))
				pinned, pinnedIndex, pinnedLUID = true, fresh.InterfaceIndex, fresh.luid
				peerState = peerNeighborState(debugIndex, debugPeer)
			}
		}
		if ipadNetDebug.peer(peerState) && (peerState == "unreachable" || peerState == "incomplete" || peerState == "absent") {
			ipadNetDebug.store(collectNetDebug("peer_"+peerState, debugIndex), true)
		}
		if v4Peer != debugVerified {
			ipadNetDebug.event("peer_verified", fmt.Sprintf("%v -> %v (%s)", debugVerified, v4Peer, macError))
			debugVerified = v4Peer
		}
		if loops%2 == 0 {
			row := windows.MibIfRow2{InterfaceIndex: debugIndex}
			if windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row) == nil {
				ipadNetDebug.counter(NetDebugCounter{InPkts: row.InUcastPkts, OutPkts: row.OutUcastPkts, InOctets: row.InOctets, OutOctets: row.OutOctets})
			}
		}
		if loops%10 == 0 {
			ipadNetDebug.store(collectNetDebug("periodic", debugIndex), false)
		}
		s.update(func(r *ApplicationResult) { r.PeerIPv4NeighborVerified = v4Peer })
		if v4Peer {
			recordUnpairedExperimentEvent("ipv4_neighbor_verified_not_arp_capture")
			recordConnectionStage("ipv4_neighbor_verified", "same_usb_peer_ipv4_mac_matched")
		}
		if loops%2 == 0 && !s.snapshot().SunshineClientTCPObserved {
			ok, queryError := sunshineNativeTCP(false, net.ParseIP(plan.ServerIP), net.ParseIP(plan.PeerIP()), 0)
			family := "IPv4"
			if !ok {
				ok, queryError = sunshineNativeTCP(true, net.ParseIP(peer.sourceIPv6), v6, peer.ipv6Scope)
				family = "IPv6"
			}
			s.update(func(r *ApplicationResult) { r.TCPQueryError = queryError })
			if ok {
				after, postError := guard()
				m, me := targetPeerMAC(after, v6)
				if postError == "" && me == "" && m == mac && (family == "IPv6" || v4Peer) {
					s.update(func(r *ApplicationResult) {
						r.SunshineClientTCPObserved = true
						recordUnpairedExperimentEvent("sunshine_exact_peer_tcp_observed")
						r.TCPAddressFamily = family
						recordConnectionStage("sunshine_peer_tcp_observed", "exact_local_peer_established_sunshine_tcp")
					})
				}
			}
		}
		if loops%15 == 0 && !s.snapshot().SunshineClientTCPObserved {
			localOK, usbOK := sunshineServerInfo("127.0.0.1"), sunshineServerInfo(plan.ServerIP)
			s.update(func(r *ApplicationResult) { r.SunshineLoopbackHTTP = localOK; r.SunshineUSBLocalHTTP = usbOK })
			if usbOK && mdnsStop == nil {
				mdnsStop, err = registerApplicationMDNS(plan.Index, plan.ServerIP, plan.Token)
				s.update(func(r *ApplicationResult) { r.MDNSRegistered = err == ""; r.MDNSError = err })
			}
		}

	}
	s.update(func(r *ApplicationResult) {
		r.Status = "APPLICATION_TRIAL_ENDED_RESTORING"
		if r.DHCPError != "" && r.Error == "" {
			r.Error = r.DHCPError
		}
	})
	return
}

// Installed executable verification and rule generation are shared by both
// paths. Batch mode changes process count, not interface, ownership or ports.
func applicationCorePermissionScript(plan ipadsession.Plan, sharedHost bool) (string, string) {
	exe, err := os.Executable()
	if err == nil {
		err = connectioninstall.Verify(exe)
	}
	if err != nil {
		return "", "USB_CORE_EXECUTABLE_UNVERIFIED"
	}
	if !sharedHost {
		return "Write-Output 'USB_CORE_PERMISSION_READY';", ""
	}
	script, err := netconfig.CoreServicesRule(plan.GUID, plan.PeerIP(), exe)
	if err != nil {
		return "", "USB_CORE_PERMISSION_INVALID"
	}
	return script, ""
}
