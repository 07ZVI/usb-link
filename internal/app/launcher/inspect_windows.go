//go:build windows && amd64

package launcher

import (
	"suhang/usbnet/internal/app/ipadeasy"
	"suhang/usbnet/internal/app/ipadncm"
	"suhang/usbnet/internal/security/applelease"
)

func modeCheck(r *Result) ipadeasy.ModeOutcome {
	probe, pause, out := executeMode(nil)
	r.Probe, r.ServicePause = &probe, pause
	return out
}

func executeMode(previous *ipadncm.Result) (ipadncm.Result, applelease.Report, ipadeasy.ModeOutcome) {
	// USB mode control uses fresh descriptor identity and actual consent only.
	// AMDS remains in its existing state; no lease, pairing or Apple session.
	probe := ipadncm.RunSelectedNetworkOnlyAppleControl(version, applicationConsent, nil, previous)
	ready := probe.Status == "NCM_DESCRIPTORS_PRESENT" && ipadncm.HasActiveNCM(probe.Before)
	if probe.Status == "NCM_DESCRIPTORS_AFTER_REQUEST" && probe.After != nil && probe.ReenumerationSeen {
		ready = ipadncm.HasActiveNCM(*probe.After)
	}
	if !ready {
		ready = ipadncm.LocalNCMDirectModeReady(probe)
	}
	out := ipadeasy.ModeOutcome{Ready: ready}
	if !ready {
		out.Error = probe.Status
	}
	return probe, applelease.Report{}, out
}

func inspect(r *Result, system, recoveryDir string) {
	// Read-only USB information and user consent precede driver/service changes.
	if !applicationConsent() {
		r.Stage = "USB_CONNECTION_NOT_ALLOWED"
		r.Error = "USB_LAYOUT_UNCONFIRMED_DECLINED_OR_CHANGED"
		return
	}
	if err := ipadncm.ValidateIPadCandidateDevice(); err != nil {
		r.Stage, r.Error = "CANDIDATE_DEVICE_UNCONFIRMED", err.Error()
		return
	}
	r.Workflow = ipadeasy.Run(func() string {
		prepare(r, system)
		if r.Error != "" {
			return r.Error
		}
		if e := ipadncm.PrepareSimplifiedIPadNetworkAfterConsent(); e != nil {
			if notice := ipadncm.UnpairedProductDriverNotice(e.Error()); notice != "" {
				ipadncm.SetMonitorStatus("IPAD_OFFICIAL_DRIVER_VERSION_UNSUPPORTED", notice)
			}
			return e.Error()
		}
		return ""
	}, func() ipadeasy.ModeOutcome { return modeCheck(r) }, func() {
		if ipadncm.LocalNCMDirectModeReady(*r.Probe) {
			// The dedicated branch below verifies its own NIC and peer. A
			// descriptor candidate must not pass the ordinary cfg5 startup check.
			return
		}
		var start ipadncm.StartupResult
		features := ipadncm.IPadCandidateFeatures()
		if features.EventStartup && features.PersistentGrouping {
			start = ipadncm.RunStartupCheckAfterModeEventsForConfigured(version, *r.Probe, recoveryDir, applicationConsent)
		} else if features.EventStartup {
			start = ipadncm.RunStartupCheckAfterModeEvents(version, *r.Probe)
		} else {
			start = ipadncm.RunStartupCheckAfterMode(version, *r.Probe)
		}
		r.Startup = &start

	})
	r.Stage = r.Workflow.Stage
	if r.Workflow.Error != "" {
		r.Error = r.Workflow.Error
	}
	if r.Error == "" && r.Probe != nil {
		if trial, handled := ipadncm.RunLocalNCMDirectNetwork(version, recoveryDir, system, *r.Probe, applicationConsent); handled {
			applyGroupingOutcome(r, trial)
			return
		}
	}
	persistent := ipadncm.IPadCandidateFeatures().PersistentGrouping
	var reused ipadncm.GroupingResult
	var configured bool
	if persistent && r.Error == "" && r.Probe != nil {
		reused, configured = ipadncm.RunConfiguredGrouping(version, recoveryDir, system, *r.Probe, applicationConsent)
		if !configured {
			reused, configured = ipadncm.RunExistingGrouping(version, recoveryDir, system, *r.Probe, applicationConsent)
		}
	}
	if r.Error == "" && (configured || r.Startup != nil && r.Startup.Status == "NCM_PRESENT_NATIVE_DRIVER_START_FAILED") {
		trial := reused
		group := ipadncm.RunGroupingTrial
		if persistent {
			group = ipadncm.RunPersistentGrouping
		}
		if !configured {
			trial = group(version, recoveryDir, system, *r.Probe, func() bool {
				return applicationConsent()
			}, func(previous ipadncm.Result) (ipadncm.Result, string) {
				probe, pause, out := executeMode(&previous)
				r.GroupingServicePause = &pause
				return probe, out.Error
			}, applicationConsent)
		}
		applyGroupingOutcome(r, trial)
	}
}

func applyGroupingOutcome(r *Result, trial ipadncm.GroupingResult) {
	r.Grouping = &trial
	r.Stage = "GROUPING_TRIAL_COMPLETE"
	if trial.Transaction.Error != "" {
		r.Error = trial.Transaction.Error
		r.Stage = "GROUPING_TRIAL_FAILED_NO_CHANGE"
		if trial.Transaction.RestoreCompleted && trial.Transaction.JournalCleared {
			r.Stage = "GROUPING_TRIAL_FAILED_RESTORED"
		}
	}
	if trial.Transaction.RestoreError != "" {
		r.Error = trial.Transaction.RestoreError
		r.Stage = "GROUPING_RESTORE_PENDING_STOP"
	}
}
