package launcher

import "fmt"

// Each lifetime pins one authenticated login process, never a process name.
// Its renderer must finish before that process exits.
type programLoginUI struct {
	exited func() (bool, bool)
	close  func()
	show   bool
}

type programLoginUIStatus struct {
	ShowRequested bool `json:"show_requested"`
}

func (e *coreProgramExit) pruneUILocked() {
	for owner, ui := range e.uis {
		if exited, known := ui.exited(); known && exited {
			ui.close()
			delete(e.uis, owner)
		}
	}
}

func (e *coreProgramExit) registerUI(owner programExitOwner, ui *programLoginUI, show bool) (bool, error) {
	if !owner.valid() || ui == nil || ui.exited == nil || ui.close == nil {
		return false, fmt.Errorf("CORE_UI_REGISTRATION_INVALID")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	retained := false
	defer func() {
		if !retained {
			ui.close()
		}
	}()
	e.pruneUILocked()
	if e.uis[owner] != nil {
		return true, nil
	}
	if e.status.Phase != "idle" {
		return false, fmt.Errorf("CORE_EXIT_IN_PROGRESS")
	}
	for prior, existing := range e.uis {
		if prior.SID == owner.SID && prior.Session == owner.Session {
			existing.show = existing.show || show
			return false, nil
		}
	}
	if len(e.uis) >= 16 {
		return false, fmt.Errorf("CORE_UI_REGISTRATION_LIMIT")
	}
	if exited, known := ui.exited(); !known || exited {
		return false, fmt.Errorf("CORE_UI_LIFETIME_UNCONFIRMED")
	}
	if e.uis == nil {
		e.uis = make(map[programExitOwner]*programLoginUI)
	}
	e.uis[owner] = ui
	retained = true
	return true, nil
}

func (e *coreProgramExit) loginUIStatus(owner programExitOwner) *programLoginUIStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	ui := e.uis[owner]
	if ui == nil {
		return nil
	}
	status := &programLoginUIStatus{ShowRequested: ui.show}
	ui.show = false
	return status
}

func (e *coreProgramExit) uiDrainedLocked() bool {
	e.pruneUILocked()
	return len(e.uis) == 0
}

func (e *coreProgramExit) closeUILifetimes() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for owner, ui := range e.uis {
		ui.close()
		delete(e.uis, owner)
	}
}
