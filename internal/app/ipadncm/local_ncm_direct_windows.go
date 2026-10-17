//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/buildinfo"
	"suhang/usbnet/internal/diagnostics/grouptrial"
)

var localNCMDirect = newLocalNCMDirectController()
var localNCMDirectStart sync.Once

func StartLocalNCMDirect(ctx context.Context, dir string) func() {
	stop := func() {}
	localNCMDirectStart.Do(func() {
		run, cancel := context.WithCancel(ctx)
		localNCMDirect.mu.Lock()
		localNCMDirect.ctx = run
		localNCMDirect.dir = dir
		localNCMDirect.mu.Unlock()
		localNCMDirectRecoveryStatus(RestoreLocalNCMDirect(dir))
		observeOwnedDirectBinding(run, dir)
		stop = func() {
			cancel()
			localNCMDirect.masterChanged(false)
			localNCMDirectRecoveryStatus(RestoreLocalNCMDirect(dir))
		}
	})
	return stop
}
func SetLocalNCMDirectPersistence(save func(bool) error, read func() (bool, error)) {
	localNCMDirect.configure(save, read)
}
func SetLocalNCMDirectMaster(on bool) {
	localNCMDirect.masterChanged(on && buildinfo.LocalDiagnostics == "true")
}
func SetLocalNCMDirect(on bool, id string) error {
	if on && buildinfo.LocalDiagnostics != "true" {
		if len(id) == 32 && strings.Trim(id, "0123456789abcdefABCDEF") == "" {
			localNCMDirect.mu.Lock()
			localNCMDirect.state.RejectedID = id
			localNCMDirect.state.RejectedError = "DIRECT_LOCAL_DIAGNOSTICS_REQUIRED"
			localNCMDirect.mu.Unlock()
		}
		return errors.New("DIRECT_LOCAL_DIAGNOSTICS_REQUIRED")
	}
	return localNCMDirect.set(on, id)
}
func LocalNCMDirectDiagnostics() any { return localNCMDirect.snapshot() }
func localNCMDirectRecoveryStatus(err error) {
	localNCMDirect.recoveryStatus(err)
}

// AMDS and other existing diagnostics keep calling RunNetworkOnlyAppleControl.
// A selection is sampled for this ordinary connection, never retrofitted into
// an already-running application session or a verified-root reactivation.
func RunSelectedNetworkOnlyAppleControl(version string, consent func() bool, acquire func() (func(), bool), previous *Result) Result {
	localNCMDirectOperation.Lock()
	localNCMDirect.mu.Lock()
	dir := localNCMDirect.dir
	rev := localNCMDirect.revision
	selected := localNCMDirect.master && localNCMDirect.state.Requested && localNCMDirect.state.Persistence == "saved" && buildinfo.LocalDiagnostics == "true"
	localNCMDirect.mu.Unlock()
	if selected && dir != "" {
		s := Inspect()
		if _, _, live := directLiveIntent(s); live && consent != nil && consent() {
			localNCMDirectOperation.Unlock()
			return Result{Version: version, Status: directNetworkModeStatus, Before: s, After: &s, USBIdentifiersVerified: true, IdentitySource: "LOCAL_OWNED_DIRECT_MODE_SAME_AUTHORIZED_ATTEMPT", ReenumerationSeen: true}
		}
	}
	if dir != "" {
		if e := restoreLocalNCMDirectLocked(dir); e != nil {
			localNCMDirectRecoveryStatus(e)
			localNCMDirectOperation.Unlock()
			return Result{Version: version, Status: e.Error()}
		}
		localNCMDirectRecoveryStatus(nil)
	}
	if !selected || previous != nil {
		localNCMDirectOperation.Unlock()
		return RunNetworkOnlyAppleControl(version, consent, acquire, previous)
	}
	defer localNCMDirectOperation.Unlock()
	if dir == "" || !localNCMDirect.allowed(rev) {
		return Result{Version: version, Status: "DIRECT_NOT_READY"}
	}
	localNCMDirect.mu.Lock()
	localNCMDirect.running = true
	localNCMDirect.state.Busy = true
	localNCMDirect.state.Effective = false
	localNCMDirect.state.NetworkReady = false
	localNCMDirect.state.Phase = "preparing"
	localNCMDirect.state.Error = ""
	localNCMDirect.state.ModeRequested = 0
	localNCMDirect.state.ModeRequests = 0
	localNCMDirect.state.Configurations = nil
	localNCMDirect.state.Nodes = nil
	localNCMDirect.state.Binding = nil
	localNCMDirect.state.Network = nil
	localNCMDirect.state.NodesOmitted = 0
	localNCMDirect.state.ConfigurationsOmitted = 0
	localNCMDirect.state.CurrentConfiguration = 0
	localNCMDirect.state.OriginalProbe = nil
	localNCMDirect.state.ObservationRead = "not_sampled"
	localNCMDirect.state.TargetMatched = false
	localNCMDirect.mu.Unlock()
	a := &localDirectRun{owner: localNCMDirect, revision: rev, dir: dir, consent: consent}
	r := runWithSelectedControlLease(version, consent, acquire, true, nil, a, true)
	localNCMDirect.mu.Lock()
	localNCMDirect.running = false
	localNCMDirect.state.Busy = localNCMDirect.state.Persistence == "saving" || localNCMDirect.state.Persistence == "loading"
	if r.Status == directNetworkModeStatus {
		localNCMDirect.state.Phase = "direct_descriptors_verified_network_pending"
		localNCMDirect.state.Error = ""
	} else if r.Status != "NCM_DESCRIPTORS_AFTER_REQUEST" {
		localNCMDirect.state.Error = r.Status
		localNCMDirect.state.Phase = "experiment_incomplete"
		if localNCMDirect.state.RecoveryRequired {
			localNCMDirect.state.Phase = "replug_required"
		}
	}
	localNCMDirect.mu.Unlock()
	return r
}

type localDirectRun struct {
	owner    *localNCMDirectController
	revision uint64
	dir      string
	consent  func() bool
	journal  localNCMDirectJournal
	armed    bool
}

func (a *localDirectRun) authorized() bool {
	return a.owner.allowed(a.revision) && a.consent != nil && a.consent()
}
func (a *localDirectRun) open(ctx context.Context, n Node, path string) (modeControl, string, error) {
	if !a.authorized() {
		return nil, "DIRECT_SELECTION_CANCELLED", windows.ERROR_CANCELLED
	}
	c, stage, e := openAppleControl(ctx, n, path)
	if e != nil {
		return nil, stage, e
	}
	return &localDirectControl{appleControl: c, trial: a}, stage, nil
}
func (a *localDirectRun) prepare(ctx context.Context, before Snapshot, probe []byte, consent func() bool) error {
	if ctx.Err() != nil || !a.authorized() || !bytes.Equal(probe, []byte{3, 3, 3, 0}) || !networkOnlyUSBEligible(before) || before.Devices[0].CurrentConfiguration != 3 {
		return errors.New("DIRECT_INITIAL_IDENTITY_OR_CONSENT_UNPROVEN")
	}
	d := before.Devices[0]
	j := localNCMDirectJournal{Schema: 1, Root: exactIPadRoot(before), Hub: d.hub, Port: d.port, SerialSHA256: d.USBSerialSHA256, OriginalConfiguration: d.CurrentConfiguration, OriginalConfigurationSHA256: directConfigurationDigest(d.Configurations, d.CurrentConfiguration), OriginalProbe: append([]byte(nil), probe...), RequestedMode: 5}
	fresh := inventory(ctx)
	if ctx.Err() != nil || !directOriginalLayout(j, fresh) || !a.authorized() {
		return errors.New("DIRECT_TARGET_CHANGED_BEFORE_INTENT")
	}
	if e := saveLocalNCMDirectJournal(a.dir, j, nil); e != nil {
		a.owner.mu.Lock()
		a.owner.state.RecoveryRequired = true
		a.owner.mu.Unlock()
		return e
	}
	a.journal = j
	a.armed = true
	a.owner.mu.Lock()
	a.owner.state.RecoveryRequired = true
	a.owner.state.OriginalConfiguration = j.OriginalConfiguration
	a.owner.state.OriginalProbe = append([]byte(nil), probe...)
	a.owner.state.Phase = "intent_saved"
	a.owner.mu.Unlock()
	return nil
}

type localDirectControl struct {
	*appleControl
	trial *localDirectRun
}

func (c *localDirectControl) Control(rt, request byte, value, index uint16, out []byte) (uint32, error) {
	if request != 0x52 || index != 5 {
		return c.appleControl.Control(rt, request, value, index, out)
	}
	if rt != 0xc0 || value != 0 || len(out) != 1 || c.ctx.Err() != nil || !c.trial.armed || !c.trial.authorized() || verifyDirectJournal(c.trial.dir, c.trial.journal) != nil {
		return 0, windows.ERROR_ACCESS_DENIED
	}
	fresh := inventory(c.ctx)
	if c.ctx.Err() != nil || !directOriginalLayout(c.trial.journal, fresh) || !c.trial.authorized() {
		return 0, windows.ERROR_ACCESS_DENIED
	}
	packet := localDirectMode5Packet()
	header := append([]byte(nil), packet[:8]...)
	c.trial.noteRequest(5)
	n, e := ioctl(c.ctx, c.file, 0x2200a0, packet)
	if e != nil {
		return 0, e
	}
	count, e := appleModeReply(header, packet, n, out)
	if e != nil {
		return 0, windows.ERROR_INVALID_DATA
	}
	return count, nil
}
func (a *localDirectRun) noteRequest(mode int) {
	a.owner.mu.Lock()
	defer a.owner.mu.Unlock()
	a.owner.state.ModeRequested = mode
	a.owner.state.ModeRequests++
	if mode == 5 {
		j := a.journal
		a.owner.issued = &j
		a.owner.issuedContext = connectionContext()
		a.owner.issuedRevision = a.revision
	}
	// This counts software submissions, not successful bus acknowledgements.
	a.owner.state.Phase = "mode_request_submitting"
}

func (a *localDirectRun) observe(ctx context.Context, r *Result) {
	for i := 0; i < 8 && ctx.Err() == nil; i++ {
		t := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
		if ctx.Err() != nil {
			break
		}
		s := inventory(ctx)
		r.After = &s
		a.recordSnapshot(s)
		if directTargetMatches(a.journal, s) && directOnlyNCMLayout(s.Devices[0].Configurations, s.Devices[0].CurrentConfiguration) {
			r.ReenumerationSeen = true
			r.Status = "DIRECT_NCM_TOPOLOGY_UNSUPPORTED_REPLUG_REQUIRED"
			if directNetworkTopology(s.Devices[0].Configurations, s.Devices[0].CurrentConfiguration) && a.authorized() {
				r.Status = directNetworkModeStatus
			}
			return
		}
	}
	// A surviving, fully proven initial Apple control interface permits the
	// ordinary mode-3 fallback. A direct-only interface never authorizes reset.
	if ctx.Err() == nil && a.authorized() && a.tryFallback(ctx, r) {
		return
	}
	r.Status = "DIRECT_MODE_NOT_VERIFIED_REPLUG_REQUIRED"
}
func (a *localDirectRun) recordSnapshot(s Snapshot) {
	var configs []Configuration
	omitted := 0
	if len(s.Devices) == 1 {
		for _, c := range s.Devices[0].Configurations {
			if c.Value == s.Devices[0].CurrentConfiguration && len(c.Interfaces) <= 4 && len(c.Associations) <= 2 {
				valid := true
				for _, i := range c.Interfaces {
					if len(i.Endpoints) > 3 || len(i.Functions) > 4 || len(i.Slaves) > 2 {
						valid = false
					}
				}
				if valid && len(configs) == 0 {
					configs = append(configs, c)
				} else {
					omitted++
				}
			} else {
				omitted++
			}
		}
	}
	p := trustPNPState{Read: "ok"}
	if s.Error != "" || s.ConnectionReadErrors != 0 {
		p.Read = "query_failed"
	}
	for _, n := range s.Nodes {
		if !strings.HasPrefix(strings.ToUpper(n.IDPrefix), `USB\VID_05AC&PID_12AB`) {
			continue
		}
		role := "other"
		if strings.EqualFold(n.IDPrefix, `USB\VID_05AC&PID_12AB`) {
			role = "R"
		} else {
			for _, v := range []string{"00", "01", "02", "03", "04", "05"} {
				if strings.HasSuffix(strings.ToUpper(n.IDPrefix), "&MI_"+v) {
					role = v
				}
			}
		}
		service := "U"
		switch strings.ToLower(n.Service) {
		case "usbncm":
			service = "N"
		case "usbccgp":
			service = "C"
		case "winusb":
			service = "W"
		case "wudfwpdmtp":
			service = "P"
		case "":
			service = "X"
		}
		p.Nodes = append(p.Nodes, trustNodeState{Role: role, Service: service, Problem: n.Problem, Readable: nodeCMReadable(n), Started: grouptrial.NativeStartObserved(n.Problem, n.StateError, n.DevNodeStatus), Restart: grouptrial.NeedsWindowsRestart(n.DevNodeStatus)})
	}
	p = normalizeTrustPNP(p)
	a.owner.mu.Lock()
	defer a.owner.mu.Unlock()
	if len(s.Devices) == 1 {
		a.owner.state.CurrentConfiguration = s.Devices[0].CurrentConfiguration
	}
	a.owner.state.ObservationRead = p.Read
	a.owner.state.TargetMatched = directTargetMatches(a.journal, s)
	a.owner.state.Configurations = cloneDirectConfigurations(configs)
	a.owner.state.ConfigurationsOmitted = omitted
	a.owner.state.Nodes = p.Nodes
	a.owner.state.NodesOmitted = p.Omitted
}
func (a *localDirectRun) tryFallback(ctx context.Context, r *Result) bool {
	s := inventory(ctx)
	if !directOriginalLayout(a.journal, s) || !a.authorized() {
		return false
	}
	for _, node := range s.Nodes {
		for _, path := range node.paths {
			w, _, e := openAppleControl(ctx, node, path)
			if e != nil {
				continue
			}
			probe := make([]byte, 4)
			done := RecordConnectionOperation("usb_get_mode")
			n, e := w.Control(0xc0, 0x45, 0, 0, probe)
			done()
			if e != nil || n != 4 || !bytes.Equal(probe, a.journal.OriginalProbe) {
				w.Close()
				continue
			}
			fresh := inventory(ctx)
			if ctx.Err() != nil || !directOriginalLayout(a.journal, fresh) || !a.authorized() {
				w.Close()
				return false
			}
			next := a.journal
			next.RequestedMode = 3
			if saveLocalNCMDirectJournal(a.dir, next, &a.journal) != nil {
				w.Close()
				return false
			}
			a.journal = next
			fresh = inventory(ctx)
			if ctx.Err() != nil || !directOriginalLayout(a.journal, fresh) || !a.authorized() || verifyDirectJournal(a.dir, a.journal) != nil {
				w.Close()
				return false
			}
			done = RecordConnectionOperation("usb_mode_switch")
			a.noteRequest(3)
			reply := []byte{255}
			_, _ = w.Control(0xc0, 0x52, 0, 3, reply)
			w.Close()
			done()
			for i := 0; i < 8 && ctx.Err() == nil; i++ {
				t := time.NewTimer(time.Second)
				select {
				case <-ctx.Done():
					t.Stop()
				case <-t.C:
				}
				if ctx.Err() != nil {
					break
				}
				after := inventory(ctx)
				r.After = &after
				a.recordSnapshot(after)
				if directOrdinaryFallback(a.journal, after) {
					if !a.authorized() || BindPhotoIsolationTarget(after) != nil || BindLocalPhotoPolicyTarget(after) != nil {
						return false
					}
					if clearLocalNCMDirectJournal(a.dir, a.journal) != nil {
						return false
					}
					r.Status = "NCM_DESCRIPTORS_AFTER_REQUEST"
					r.ReenumerationSeen = true
					a.owner.mu.Lock()
					a.owner.state.RecoveryRequired = false
					a.owner.state.Phase = "direct_failed_fallback_mode3_verified"
					a.owner.state.Error = "DIRECT_FALLBACK_TO_ORDINARY_MODE3"
					a.owner.mu.Unlock()
					return true
				}
			}
			return false
		}
	}
	return false
}
