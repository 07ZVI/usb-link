package connectioninstall

import (
	"suhang/usbnet/internal/app/remoteupdate"
	"time"
)

// One bootstrap observes one exact live candidate/core pair. No disk receipt or
// previous UI process can donate elapsed health time to a replacement.
type coreBootstrapIdentity struct {
	Job, Hash                       string
	CandidatePID, CorePID           uint32
	CandidateCreation, CoreCreation uint64
}
type coreBootstrapReadiness struct {
	identity coreBootstrapIdentity
	last     time.Time
	health   remoteupdate.Readiness
}

// Only a recorded attempted failed candidate fences normal cold boot. A staged
// or cancelled release and completed deployment do not own a new core process.
func coreFailedCandidateRecorded(status string, pid uint32, creation uint64) bool {
	if pid == 0 || creation == 0 {
		return false
	}
	switch status {
	case "rollback", "rollback_running", "rollback_failed", "failed":
		return true
	}
	return false
}

func (r *coreBootstrapReadiness) observe(now time.Time, identity coreBootstrapIdentity, healthy bool) bool {
	if !healthy || identity.Job == "" || identity.Hash == "" || identity.CandidatePID == 0 || identity.CorePID == 0 || identity.CandidateCreation == 0 || identity.CoreCreation == 0 {
		*r = coreBootstrapReadiness{}
		return false
	}
	if r.identity != identity || r.last.IsZero() || now.Before(r.last) || now.Sub(r.last) > 3*time.Second {
		*r = coreBootstrapReadiness{identity: identity}
	}
	r.last = now
	return r.health.Observe(now, true)
}
