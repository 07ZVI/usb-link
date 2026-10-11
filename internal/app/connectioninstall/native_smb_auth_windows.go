//go:build windows && amd64

package connectioninstall

import (
	"crypto/sha256"
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Called under smbAccountMu. Cache only this encrypted receipt for 30 seconds
// to prevent repeated view/copy clicks from repeatedly attempting a bad logon.
var smbCredentialCheck struct {
	name, sid string
	blob      [32]byte
	at        time.Time
	err       error
}

func verifySMBNetworkCredential(a smbAccount, password []byte) error {
	key := sha256.Sum256(a.Password)
	if smbCredentialCheck.name == a.Name && smbCredentialCheck.sid == a.SID && smbCredentialCheck.blob == key && time.Since(smbCredentialCheck.at) < 30*time.Second {
		return smbCredentialCheck.err
	}
	check := func() error {
		proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("LogonUserW")
		if err := proc.Find(); err != nil {
			return fmt.Errorf("SMB_ACCOUNT_AUTH_CHECK_UNAVAILABLE")
		}
		encoded := windows.StringToUTF16(string(password))
		defer clear(encoded)
		var token windows.Token
		// Local SAM, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT. No desktop
		// logon, credential caching, impersonation or network file writes.
		ok, _, err := proc.Call(uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(a.Name))), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("."))), uintptr(unsafe.Pointer(&encoded[0])), 3, 0, uintptr(unsafe.Pointer(&token)))
		runtime.KeepAlive(encoded)
		if token != 0 {
			defer token.Close()
		}
		if ok == 0 {
			return fmt.Errorf("SMB_ACCOUNT_AUTH_CHECK_FAILED: Windows 未接受這個帳戶的網路登入，請依錯誤核對帳戶或密碼。Windows: %v", err)
		}
		user, err := token.GetTokenUser()
		if err != nil || user.User.Sid.String() != a.SID {
			return fmt.Errorf("SMB_ACCOUNT_AUTH_IDENTITY_CHANGED")
		}
		return nil
	}
	err := check()
	smbCredentialCheck.name, smbCredentialCheck.sid, smbCredentialCheck.blob, smbCredentialCheck.at, smbCredentialCheck.err = a.Name, a.SID, key, time.Now(), err
	return err
}

var smbAccountReadState struct {
	sync.Mutex
	count        uint64
	exists       bool
	authVerified bool
	problem      string
	at           time.Time
}

func recordSMBAccountRead(v SMBAccountView) {
	smbAccountReadState.Lock()
	defer smbAccountReadState.Unlock()
	smbAccountReadState.count++
	smbAccountReadState.exists, smbAccountReadState.problem, smbAccountReadState.at = v.Exists, v.Problem, time.Now()
	smbAccountReadState.authVerified = v.AuthenticationVerified
}

func nativeSMBAccountReadDiagnostics() map[string]any {
	smbAccountReadState.Lock()
	defer smbAccountReadState.Unlock()
	return map[string]any{"local_reads": smbAccountReadState.count, "account_exists": smbAccountReadState.exists, "authentication_verified": smbAccountReadState.authVerified, "problem": smbAccountReadState.problem, "observed_utc": smbAccountReadState.at, "scope": "last explicit local account read; no username, password or credential hash"}
}
