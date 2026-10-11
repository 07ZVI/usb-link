package grouptrial

import "testing"

func TestRecoveryTargetCannotExpandBeyondRecordedIPadSoftwareKey(t *testing.T) {
	root := `USB\VID_05AC&PID_12AB\FAKE_TEST_ID`
	driver := `{88BAE032-5A81-49F0-BC3D-A4FF138216D6}\0001`
	if !ValidRecoveryTarget(root, driver, 1, true) {
		t.Fatal("valid fixed target rejected")
	}
	for _, bad := range []string{`USB\VID_05AC&PID_1903\FAKE_TEST_ID`, `USB\VID_05AC&PID_12AB&MI_01\FAKE_TEST_ID`, root + `\subkey`, root + "/../x", "*"} {
		if ValidRecoveryTarget(bad, driver, 1, true) {
			t.Fatal("bad root accepted", bad)
		}
	}
	for _, bad := range []string{driver + `\subkey`, `..\Services\UsbNcm`, `{00000000-0000-0000-0000-000000000000}\0001`, driver + "0"} {
		if ValidRecoveryTarget(root, bad, 1, true) {
			t.Fatal("bad key accepted", bad)
		}
	}
	if ValidRecoveryTarget(root, driver, 2, true) || ValidRecoveryTarget(root, driver, 1, false) {
		t.Fatal("unsupported original-state record accepted")
	}
}
func TestNativeStartRequiresStartedStatus(t *testing.T) {
	if !NativeStartObserved(0, "", "0x0180200a") {
		t.Fatal("started node rejected")
	}
	for _, tc := range []struct {
		problem     uint32
		err, status string
	}{{10, "", "0x01802400"}, {0, "", "0x01802400"}, {0, "CM_FAILED", "0x0180200a"}, {0, "", "invalid"}, {0, "", "0x100000008"}} {
		if NativeStartObserved(tc.problem, tc.err, tc.status) {
			t.Fatal("false started evidence", tc)
		}
	}
}

func TestRestartFlagIndependentOfStartedFlag(t *testing.T) {
	if !NeedsWindowsRestart("0x0180610a") || NeedsWindowsRestart("0x0180600a") || NeedsWindowsRestart("invalid") {
		t.Fatal("restart flag interpretation failed")
	}
}

func TestSameLaunchIdentityRejectsReplacementAtSamePort(t *testing.T) {
	root := `USB\VID_05AC&PID_12AB\SYNTHETIC-ONE`
	for _, tc := range []struct {
		physical     bool
		old, current string
		want         bool
	}{
		{true, root, root, true},
		{true, root, `usb\vid_05ac&pid_12ab\synthetic-one`, true},
		{true, root, `USB\VID_05AC&PID_12AB\SYNTHETIC-TWO`, false},
		{false, root, root, false},
		{true, "", root, false},
		{true, root, "", false},
		{true, `USB\VID_05AC&PID_12AB&MI_01\SYNTHETIC-ONE`, `USB\VID_05AC&PID_12AB&MI_01\SYNTHETIC-ONE`, false},
	} {
		if SameVerifiedRoot(tc.physical, tc.old, tc.current) != tc.want {
			t.Fatalf("unexpected binding: %+v", tc)
		}
	}
}

func TestAlreadyRestoredLayoutAvoidsAnotherDeviceRestart(t *testing.T) {
	for _, tc := range []struct {
		name, service, status  string
		absent, data03, data05 bool
		problem                uint32
		want                   bool
	}{
		{"healthy original after reboot", "usbccgp", "0x0180600a", true, true, true, 0, true},
		{"still changing registry", "usbccgp", "0x0180600a", false, true, true, 0, false},
		{"grouped layout still loaded", "usbccgp", "0x0180600a", true, false, false, 0, false},
		{"incomplete layout", "usbccgp", "0x0180600a", true, true, false, 0, false},
		{"real restart flag", "usbccgp", "0x0180610a", true, true, true, 0, false},
		{"real restart problem", "usbccgp", "0x0180600a", true, true, true, 14, false},
		{"not started", "usbccgp", "0x01806002", true, true, true, 0, false},
		{"foreign service", "WinUSB", "0x0180600a", true, true, true, 0, false},
		{"unreadable status", "usbccgp", "invalid", true, true, true, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := OriginalGroupingRestored(tc.absent, tc.service, tc.problem, tc.status, tc.data03, tc.data05); got != tc.want {
				t.Fatalf("restoration proof=%v, want %v", got, tc.want)
			}
		})
	}
}
