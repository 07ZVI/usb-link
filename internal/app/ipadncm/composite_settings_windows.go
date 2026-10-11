//go:build windows && amd64

package ipadncm

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Use SetupAPI's device-specific hardware/software keys rather than guessing
// their paths. Query only fixed values; neither key is opened with write access.
// Record absent values separately from type/length/access failures.
func readCompositeSettings(set windows.DevInfo, info *windows.DevInfoData, n *Node) {
	h, e := set.OpenDevRegKey(info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, registry.QUERY_VALUE)
	if e != nil {
		n.EnumeratorError = "OPEN_SOFTWARE_KEY_" + eno(e)
	} else {
		k := registry.Key(h)
		b, _, e := k.GetBinaryValue("EnumeratorClass")
		if e != nil {
			n.EnumeratorError = eno(e)
		} else if len(b) != 3 {
			n.EnumeratorError = "INVALID_LENGTH"
		} else {
			n.EnumeratorClass = fmt.Sprintf("%x", b)
		}
		k.Close()
	}
	h, e = set.OpenDevRegKey(info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DEV, registry.QUERY_VALUE)
	if e != nil {
		n.CompositeCapsError = "OPEN_HARDWARE_KEY_" + eno(e)
		n.OriginalConfigError = n.CompositeCapsError
		return
	}
	k := registry.Key(h)
	defer k.Close()
	read := func(name string) (*uint64, string) {
		v, typ, e := k.GetIntegerValue(name)
		if e != nil {
			return nil, eno(e)
		}
		if typ != registry.DWORD {
			return nil, "INVALID_TYPE"
		}
		return &v, ""
	}
	n.CompositeCaps, n.CompositeCapsError = read("UsbccgpCapabilities")
	n.OriginalConfig, n.OriginalConfigError = read("OriginalConfigurationValue")
}
