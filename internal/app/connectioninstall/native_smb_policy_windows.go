//go:build windows && amd64

package connectioninstall

import (
	"golang.org/x/sys/windows/registry"
)

// Fixed, read-only policy inventory. Guest share access and server enumeration
// are different access checks; successful share creation proves neither of them.
// Never return credentials, account inventories or raw security descriptors.
func nativeSMBPolicyDiagnostics() map[string]any {
	out := map[string]any{}
	for _, group := range []struct {
		path string
		keys []string
	}{
		{`SYSTEM\CurrentControlSet\Control\Lsa`, []string{"RestrictAnonymous", "RestrictAnonymousSAM", "EveryoneIncludesAnonymous", "ForceGuest"}},
		{`SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`, []string{"RestrictNullSessAccess", "RequireSecuritySignature", "EncryptData"}},
	} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, group.path, registry.QUERY_VALUE)
		for _, name := range group.keys {
			row := map[string]any{}
			if err != nil {
				row["readable"] = false
			} else {
				value, kind, e := k.GetIntegerValue(name)
				switch {
				case e == registry.ErrNotExist:
					row["present"], row["readable"] = false, true
				case e != nil || kind != registry.DWORD:
					row["readable"] = false
				default:
					row["present"], row["readable"], row["value"] = true, true, value
				}
			}
			out[name] = row
		}
		if err == nil {
			k.Close()
		}
	}
	return out
}
