package connectioninstall

import "testing"

func TestUpgradeCallbacksFailClosedAndRegisterOnlyOnce(t *testing.T) {
	if _, err := acquireIPadUpgradeAdmission(); err == nil {
		t.Fatal("missing queue owner accepted upgrade")
	}
	if remoteUSBHealthy() {
		t.Fatal("missing Mac monitor treated as normal readiness")
	}
	released := false
	RegisterIPadUpgradeAdmission(func() (func(), error) { return func() { released = true }, nil })
	release, err := acquireIPadUpgradeAdmission()
	if err != nil || release == nil {
		t.Fatal(err)
	}
	release()
	if !released {
		t.Fatal("reservation did not retain its release callback")
	}
	healthy := false
	defer func() { healthy = false }()
	RegisterRemoteUSBHealth(func() bool { return healthy })
	if remoteUSBHealthy() {
		t.Fatal("unhealthy monitor accepted")
	}
	healthy = true
	if !remoteUSBHealthy() {
		t.Fatal("independent Mac health not observed")
	}
	mustPanic := func(f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Fatal("duplicate registration accepted")
			}
		}()
		f()
	}
	mustPanic(func() { RegisterIPadUpgradeAdmission(func() (func(), error) { return nil, nil }) })
	mustPanic(func() { RegisterRemoteUSBHealth(func() bool { return true }) })
}

func TestUpgradeGuardFixedProfileBounds(t *testing.T) {
	for _, q := range []struct {
		kind    string
		seconds int
		nonce   string
		valid   bool
	}{
		{"UPGRADEGUARDON", 900, "1234567890abcdef1234567890abcdef", true},
		{"UPGRADEGUARDOFF", 0, "1234567890abcdef1234567890abcdef", true},
		{"UPGRADEGUARDSTATE", 0, "1234567890abcdef1234567890abcdef", true},
		{"UPGRADEGUARDON", 901, "1234567890abcdef1234567890abcdef", false},
		{"UPGRADEGUARDON", 0, "1234567890abcdef1234567890abcdef", false},
		{"UPGRADEGUARDOFF", 900, "1234567890abcdef1234567890abcdef", false},
		{"UPGRADEGUARDSTATE", 0, "bad nonce", false},
	} {
		if got := validMeasurement(q.kind, q.seconds, q.nonce) == nil; got != q.valid {
			t.Fatalf("%+v accepted=%v", q, got)
		}
	}
}
