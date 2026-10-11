package connectioninstall

import (
	"fmt"
	"sync"
)

// Registration installs a callback only; package initialization performs no I/O.
var ipadUpgradeAdmission struct {
	sync.Mutex
	registered bool
	acquire    func() (func(), error)
}

func RegisterIPadUpgradeAdmission(acquire func() (func(), error)) {
	ipadUpgradeAdmission.Lock()
	defer ipadUpgradeAdmission.Unlock()
	if ipadUpgradeAdmission.registered || acquire == nil {
		panic("iPad upgrade admission already registered or nil")
	}
	ipadUpgradeAdmission.registered = true
	ipadUpgradeAdmission.acquire = acquire
}
func acquireIPadUpgradeAdmission() (func(), error) {
	ipadUpgradeAdmission.Lock()
	f := ipadUpgradeAdmission.acquire
	ipadUpgradeAdmission.Unlock()
	if f == nil {
		return nil, fmt.Errorf("iPad maintenance owner unavailable")
	}
	return f()
}

// The health provider must read the independent Mac monitor without starting
// network I/O. An absent provider cannot acknowledge normal USB readiness.
var remoteUSBHealth struct {
	sync.Mutex
	registered bool
	healthy    func() bool
}

func RegisterRemoteUSBHealth(healthy func() bool) {
	remoteUSBHealth.Lock()
	defer remoteUSBHealth.Unlock()
	if remoteUSBHealth.registered || healthy == nil {
		panic("USB health provider already registered or nil")
	}
	remoteUSBHealth.registered = true
	remoteUSBHealth.healthy = healthy
}
func remoteUSBHealthy() bool {
	remoteUSBHealth.Lock()
	f := remoteUSBHealth.healthy
	remoteUSBHealth.Unlock()
	return f != nil && f()
}
