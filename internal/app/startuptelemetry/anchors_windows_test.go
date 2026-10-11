//go:build windows && amd64

package startuptelemetry

import (
	"testing"
	"unsafe"
)

func TestWTSInfoWideSDKLayout(t *testing.T) {
	if unsafe.Offsetof(wtsInfoSDK{}.Logon) != 200 || unsafe.Offsetof(wtsInfoSDK{}.Current) != 208 || unsafe.Sizeof(wtsInfoSDK{}) != 216 {
		t.Fatal("WTSINFOW SDK layout drift")
	}
}

func TestNativeAnchorsNeverExposeAccountInformation(t *testing.T) {
	a := captureNativeAnchors()
	if !a.Logon.Available && a.Logon.At != nil {
		t.Fatal("missing login assigned a time")
	}
	if a.Process.Source != "GET_PROCESS_TIMES_CREATION" || a.Logon.Source != "WTS_CURRENT_PROCESS_SESSION_LOGON_TIME" {
		t.Fatal("wrong native anchor source")
	}
}
