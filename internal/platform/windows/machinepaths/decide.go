package machinepaths

// UseNew picks the active location of a machine folder. An existing new folder
// always wins; otherwise an existing old one keeps serving a rollback-capable
// install. A fresh machine gets the new folder when its parent is usable.
func UseNew(newExists, oldExists, parentUsable bool) bool {
	if newExists {
		return true
	}
	return !oldExists && parentUsable
}

// Migration is everything the one-time old-to-new folder move depends on.
type Migration struct {
	InstallUnfinished bool // an installation transaction is not Complete/RolledBack/absent
	TransactionErr    bool // transaction state could not be read
	OldExists         bool
	NewExists         bool
	OldRepaired       bool // the protected-directory repair succeeded for the old folder
	SameVolume        bool
	ParentsPlain      bool // neither parent is a reparse point
	StoreOpened       bool // a store of this process already uses the folder
}

// Admit returns "" when the folder may be renamed, else the skip reason.
func (m Migration) Admit() string {
	switch {
	case !m.OldExists:
		return "old_absent"
	case m.StoreOpened:
		return "store_already_opened"
	case m.TransactionErr:
		return "installation_state_unreadable"
	case m.InstallUnfinished:
		return "installation_unfinished"
	case m.NewExists:
		return "new_exists"
	case !m.OldRepaired:
		return "old_protection_unverified"
	case !m.SameVolume:
		return "different_volume"
	case !m.ParentsPlain:
		return "parent_unusable"
	}
	return ""
}
