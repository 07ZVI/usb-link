//go:build windows && amd64

package netconfig

import (
	"strings"
	"suhang/usbnet/internal/transport/usbaddress"

	"golang.org/x/sys/windows"
)

// Inspect installed (including non-present) nodes only when the ordinary
// present-node observation found no binding. Unlike recovery, this never
// returns a native target, opens an adapter, removes a node or changes a flag.
// Official Wintun 0.14.1 uses this broader set for orphan cleanup; we observe
// it solely to distinguish orphaned nodes from missing/broken GUID bindings.
func inspectInstalledHostNodes() *HostInstalledNodeObservation {
	o := &HostInstalledNodeObservation{ObservationOnly: true}
	class, _ := windows.GUIDFromString(hostNetClass)
	set, err := windows.SetupDiGetClassDevsEx(&class, "", 0, 0, 0, "")
	if err != nil {
		o.QueryError = "USB_HOST_INSTALLED_ENUMERATION_FAILED"
		return o
	}
	defer set.Close()
	for i := 0; i < 4096; i++ {
		info, err := set.EnumDeviceInfo(i)
		if err == windows.ERROR_NO_MORE_ITEMS {
			o.Complete = true
			return o
		}
		if err != nil {
			o.QueryError = "USB_HOST_INSTALLED_ENUMERATION_FAILED"
			return o
		}
		o.Enumerated++
		key, err := set.OpenDevRegKey(info, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_QUERY_VALUE)
		if err == windows.ERROR_FILE_NOT_FOUND {
			o.MissingDriverKeys++
			continue
		}
		if err != nil {
			o.QueryError = "USB_HOST_INSTALLED_BINDING_UNREADABLE"
			return o
		}
		guid, found, err := nativeHostRegistryGUID(key)
		windows.RegCloseKey(key)
		if err != nil {
			o.QueryError = "USB_HOST_INSTALLED_BINDING_INVALID"
			return o
		}
		if !found {
			o.MissingNetworkGUIDs++
			continue
		}
		if !strings.EqualFold(guid, usbaddress.HostGUID) {
			o.ForeignNetworkGUIDs++
			continue
		}
		o.BindingMatches++
		if len(o.Candidates) == 4 {
			o.CandidatesTruncated = true
			continue
		}
		c := HostInstalledCandidateObservation{}
		n, err := readNativeHostNode(set, info, guid)
		c.IdentityValid = err == nil
		if err != nil {
			// readNativeHostNode returns fixed product codes, never paths/IDs.
			c.IdentityError = err.Error()
		}
		err = windows.CM_Get_DevNode_Status(&c.Status, &c.Problem, info.DevInst, 0)
		c.StateReadable = err == nil
		if code, ok := err.(windows.CONFIGRET); ok {
			c.StateError = uint32(code)
		}
		p, err := set.DeviceInstallParams(info)
		c.InstallFlagsReadable = err == nil && p != nil
		if c.InstallFlagsReadable {
			c.RestartRequired = p.Flags&(windows.DI_NEEDREBOOT|windows.DI_NEEDRESTART) != 0
		}
		if !n.StateReadable && n.StateError == uint32(windows.CR_NO_SUCH_DEVNODE) {
			proof, err := readNativeHostNonpresentProof(&nativeHostTarget{set: set, info: info, node: n})
			if err != nil {
				c.NonpresentProofError = err.Error()
			}
			if proof.NormalReadable {
				c.NormalResult = &proof.NormalResult
			}
			if proof.PhantomReadable {
				c.PhantomResult, c.PhantomExact = &proof.PhantomResult, &proof.PhantomExact
			}
			c.ConfigReadable, c.CMConfigReadable = &proof.ConfigReadable, &proof.CMConfigReadable
			if proof.ConfigReadable {
				c.ConfigType, c.ConfigSize, c.ConfigValue = &proof.ConfigType, &proof.ConfigSize, &proof.Config
			}
			if proof.CMConfigReadable {
				c.CMConfigType, c.CMConfigSize, c.CMConfigValue = &proof.CMConfigType, &proof.CMConfigSize, &proof.CMConfig
			}
		}
		o.Candidates = append(o.Candidates, c)
	}
	o.QueryError = "USB_HOST_INSTALLED_ENUMERATION_LIMIT"
	return o
}
