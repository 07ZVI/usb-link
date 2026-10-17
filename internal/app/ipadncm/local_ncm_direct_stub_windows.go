//go:build windows && amd64 && !usblink_local_remote

package ipadncm

import (
	"context"
	"errors"
	"sync"
)

var localNCMDirectPublic struct {
	sync.Mutex
	dir string
	err error
}

func StartLocalNCMDirect(_ context.Context, dir string) func() {
	e := RestoreLocalNCMDirect(dir)
	localNCMDirectPublic.Lock()
	localNCMDirectPublic.dir = dir
	localNCMDirectPublic.err = e
	localNCMDirectPublic.Unlock()
	return func() {}
}
func SetLocalNCMDirectPersistence(func(bool) error, func() (bool, error)) {}
func SetLocalNCMDirectMaster(bool)                                        {}
func SetLocalNCMDirect(on bool, _ string) error {
	if on {
		return errors.New("DIRECT_LOCAL_BUILD_REQUIRED")
	}
	return nil
}
func LocalNCMDirectDiagnostics() any {
	localNCMDirectPublic.Lock()
	defer localNCMDirectPublic.Unlock()
	if localNCMDirectPublic.err != nil {
		return map[string]any{"available": false, "phase": "replug_required", "recovery_required": true, "error": "DIRECT_RECOVERY_PENDING"}
	}
	return nil
}
func RunSelectedNetworkOnlyAppleControl(version string, consent func() bool, acquire func() (func(), bool), previous *Result) Result {
	localNCMDirectPublic.Lock()
	dir := localNCMDirectPublic.dir
	localNCMDirectPublic.Unlock()
	if dir != "" {
		e := RestoreLocalNCMDirect(dir)
		localNCMDirectPublic.Lock()
		localNCMDirectPublic.err = e
		localNCMDirectPublic.Unlock()
		if e != nil {
			return Result{Version: version, Status: e.Error()}
		}
	}
	return RunNetworkOnlyAppleControl(version, consent, acquire, previous)
}

func LocalNCMDirectModeReady(Result) bool { return false }
func RunLocalNCMDirectNetwork(string, string, string, Result, func() bool) (GroupingResult, bool) {
	return GroupingResult{}, false
}
func localDirectCurrentConsentLayout(*ConnectionAuthorization, Snapshot) bool { return false }
func localDirectDescriptorAttachment(Snapshot) usbDescriptorAttachment {
	return usbDescriptorAttachment{}
}
