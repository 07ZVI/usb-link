//go:build windows && amd64

package ipadncm

func LocalTrustServiceTrialSnapshot() LocalTrustServiceTrial {
	amdsDiagnosticJob.Lock()
	defer amdsDiagnosticJob.Unlock()
	s := amdsDiagnosticJob.TrialObservation
	s.Requested = amdsDiagnosticJob.LocalTrustTrial
	if !s.Requested {
		return s
	}
	s.Running, s.Phase = amdsDiagnosticJob.Running, amdsDiagnosticJob.Phase
	s.AttemptBefore, s.AttemptAfter = amdsDiagnosticJob.AttemptBefore, amdsDiagnosticJob.AttemptAfter
	if r := amdsDiagnosticJob.Result; r != nil {
		s.Restored, s.Before, s.During, s.After, s.StartType = r.Restored, r.Before, r.During, r.After, r.OriginalStartType
		s.Error, s.RestoreError = r.Error, r.RestoreError
		if len(s.Error) > 80 {
			s.Error = s.Error[:80]
		}
		if len(s.RestoreError) > 80 {
			s.RestoreError = s.RestoreError[:80]
		}
	}
	return s
}

func publishLocalTrustTrialObservation(r AMDSModeDiagnostic) {
	amdsDiagnosticJob.Lock()
	defer amdsDiagnosticJob.Unlock()
	amdsDiagnosticJob.TrialObservation = LocalTrustServiceTrial{Before: r.Before, During: r.During, After: r.After, StartType: r.OriginalStartType, Restored: r.Restored}
}
