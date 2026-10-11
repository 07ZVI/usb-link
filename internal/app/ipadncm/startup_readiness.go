package ipadncm

type startupReadiness struct {
	Controls, StartedControls, FailedControls, OrphanData int
	UngroupedRootConfirmed                                bool
}

func (e startupReadiness) settled() bool {
	return e.Controls == 2 && (e.StartedControls == 2 || e.UngroupedRootConfirmed && e.FailedControls == 2 && e.OrphanData == 2)
}
