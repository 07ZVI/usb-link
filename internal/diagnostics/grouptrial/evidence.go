package grouptrial

import (
	"regexp"
	"strconv"
	"strings"
)

var rootIDPattern = regexp.MustCompile(`(?i)^USB\\VID_05AC&PID_12AB\\[A-Z0-9&._-]{1,200}$`)
var driverKeyPattern = regexp.MustCompile(`(?i)^\{88BAE032-5A81-49F0-BC3D-A4FF138216D6\}\\[0-9]{4}$`)

func ValidRecoveryTarget(root, driver string, version int, absent bool) bool {
	return version == 1 && absent && rootIDPattern.MatchString(root) && driverKeyPattern.MatchString(driver)
}

// A problem-free devnode is not enough: require DN_STARTED from a successful
// CM_Get_DevNode_Status observation. This is still not IP/network proof.
func NativeStartObserved(problem uint32, stateError, status string) bool {
	v, e := strconv.ParseUint(status, 0, 32)
	return e == nil && problem == 0 && stateError == "" && v&8 != 0
}

func NeedsWindowsRestart(status string) bool {
	v, e := strconv.ParseUint(status, 0, 32)
	return e == nil && v&0x100 != 0 // DN_NEED_RESTART, from cfgmgr32
}

// A healthy original composite layout is positive restoration evidence. A
// deleted registry value alone cannot prove that the loaded layout changed.
func OriginalGroupingRestored(alreadyAbsent bool, service string, problem uint32, status string, data03, data05 bool) bool {
	return alreadyAbsent && strings.EqualFold(service, "usbccgp") &&
		NativeStartObserved(problem, "", status) && !NeedsWindowsRestart(status) && data03 && data05
}

// Reusing same-launch identity requires both physical position and the exact
// private root, never just a matching PID at a recycled port.
func SameVerifiedRoot(physicalMatch bool, previous, current string) bool {
	return physicalMatch && rootIDPattern.MatchString(previous) && rootIDPattern.MatchString(current) && strings.EqualFold(previous, current)
}
