package machinepaths

import "testing"

func TestUseNew(t *testing.T) {
	for _, c := range []struct{ n, o, p, want bool }{
		{true, true, true, true}, {true, false, false, true}, {false, true, true, false},
		{false, false, true, true}, {false, false, false, false},
	} {
		if got := UseNew(c.n, c.o, c.p); got != c.want {
			t.Errorf("UseNew(%v,%v,%v)=%v", c.n, c.o, c.p, got)
		}
	}
}

func TestAdmit(t *testing.T) {
	ok := Migration{OldExists: true, OldRepaired: true, SameVolume: true, ParentsPlain: true}
	if r := ok.Admit(); r != "" {
		t.Fatal(r)
	}
	for want, mutate := range map[string]func(*Migration){
		"old_absent":                    func(m *Migration) { m.OldExists = false },
		"store_already_opened":          func(m *Migration) { m.StoreOpened = true },
		"installation_state_unreadable": func(m *Migration) { m.TransactionErr = true },
		"installation_unfinished":       func(m *Migration) { m.InstallUnfinished = true },
		"new_exists":                    func(m *Migration) { m.NewExists = true },
		"old_protection_unverified":     func(m *Migration) { m.OldRepaired = false },
		"different_volume":              func(m *Migration) { m.SameVolume = false },
		"parent_unusable":               func(m *Migration) { m.ParentsPlain = false },
	} {
		m := ok
		mutate(&m)
		if got := m.Admit(); got != want {
			t.Errorf("want %s got %s", want, got)
		}
	}
}
