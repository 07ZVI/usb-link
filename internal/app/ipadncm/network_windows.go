//go:build windows && amd64

package ipadncm

import (
	"fmt"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"suhang/usbnet/internal/diagnostics/grouptrial"
)

type NetworkAddress struct {
	IP           string `json:"ip"`
	PrefixLength uint8  `json:"prefix_length"`
	DadState     int32  `json:"dad_state"`
	PrefixOrigin int32  `json:"prefix_origin"`
	SuffixOrigin int32  `json:"suffix_origin"`
}
type NetworkAdapter struct {
	Node                        string           `json:"node_id_prefix"`
	Matched                     bool             `json:"exact_devnode_to_adapter_match"`
	InterfaceIndex              uint32           `json:"interface_index,omitempty"`
	IPv6InterfaceIndex          uint32           `json:"ipv6_interface_index,omitempty"`
	OperStatus                  uint32           `json:"oper_status,omitempty"`
	AdminStatus                 uint32           `json:"admin_status,omitempty"`
	InterfaceAndOperStatusFlags uint8            `json:"interface_and_oper_status_flags,omitempty"`
	MediaConnectState           uint32           `json:"media_connect_state,omitempty"`
	MTU                         uint32           `json:"mtu,omitempty"`
	ReportedTransmitBPS         uint64           `json:"reported_transmit_link_bps_not_throughput,omitempty"`
	ReportedReceiveBPS          uint64           `json:"reported_receive_link_bps_not_throughput,omitempty"`
	Addresses                   []NetworkAddress `json:"unicast_addresses,omitempty"`
	StatisticsRead              bool             `json:"statistics_read"`
	InOctets                    uint64           `json:"in_octets"`
	OutOctets                   uint64           `json:"out_octets"`
	InErrors                    uint64           `json:"in_errors"`
	OutErrors                   uint64           `json:"out_errors"`
	InDiscards                  uint64           `json:"in_discards"`
	OutDiscards                 uint64           `json:"out_discards"`
	DeltaValid                  bool             `json:"same_adapter_counter_delta_valid"`
	DeltaIn                     uint64           `json:"passive_in_octets_delta"`
	DeltaOut                    uint64           `json:"passive_out_octets_delta"`
	Error                       string           `json:"error,omitempty"`
	instanceID                  string           // Exact local native node, never exported.
	key                         string
	luid                        uint64
}
type NetworkSample struct {
	ElapsedMS       int64            `json:"elapsed_ms"`
	TargetConfirmed bool             `json:"same_exact_root_active_ncm_owned_grouping"`
	Adapters        []NetworkAdapter `json:"healthy_ncm_adapters,omitempty"`
	Error           string           `json:"error,omitempty"`
}
type NetworkObservation struct {
	Status                 string          `json:"status"`
	PassiveOnly            bool            `json:"passive_read_only"`
	Samples                []NetworkSample `json:"samples,omitempty"`
	PassiveTrafficObserved bool            `json:"passive_counter_growth_observed"`
	NetworkVerified        bool            `json:"network_verified"`
	MoonlightVerified      bool            `json:"moonlight_verified"`
}

// Read the association from each exact current healthy USB NCM devnode, not
// a friendly name, all Ethernet interfaces, or an interface index from a log.
func readNCMAdapters(s Snapshot) []NetworkAdapter {
	var out []NetworkAdapter
	for _, n := range s.Nodes {
		if !strings.EqualFold(n.Service, "UsbNcm") || !grouptrial.NativeStartObserved(n.Problem, n.StateError, n.DevNodeStatus) {
			continue
		}
		r := NetworkAdapter{Node: n.IDPrefix, instanceID: n.instanceID}
		set, e := windows.SetupDiGetClassDevsEx(nil, "USB", 0, windows.DIGCF_PRESENT|windows.DIGCF_ALLCLASSES, 0, "")
		if e != nil {
			r.Error = "NCM_MAPPING_ENUM_FAILED"
			out = append(out, r)
			continue
		}
		guid := ""
		complete := false
		for i := 0; i < 4096; i++ {
			info, err := set.EnumDeviceInfo(i)
			if err == windows.ERROR_NO_MORE_ITEMS {
				complete = true
				break
			}
			if err != nil {
				r.Error = "NCM_MAPPING_ENUM_FAILED"
				break
			}
			id, err := set.DeviceInstanceID(info)
			if err != nil {
				r.Error = "NCM_MAPPING_ID_UNAVAILABLE"
				break
			}
			if !strings.EqualFold(id, n.instanceID) {
				continue
			}
			var status, problem uint32
			if windows.CM_Get_DevNode_Status(&status, &problem, info.DevInst, 0) != nil || problem != 0 || status&8 == 0 || status&0x100 != 0 {
				r.Error = "NCM_NODE_CHANGED_BEFORE_MAPPING"
				break
			}
			service, err := set.DeviceRegistryProperty(info, windows.SPDRP_SERVICE)
			if err != nil || !strings.EqualFold(fmt.Sprint(service), "UsbNcm") {
				r.Error = "NCM_SERVICE_CHANGED_BEFORE_MAPPING"
				break
			}
			value, err := set.DeviceRegistryProperty(info, windows.SPDRP_DRIVER)
			key, ok := value.(string)
			if err != nil || !ok || !netDriverKeyPattern.MatchString(key) {
				r.Error = "NCM_NET_CLASS_KEY_UNCONFIRMED"
				break
			}
			k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Class\`+key, registry.QUERY_VALUE)
			if err != nil {
				r.Error = "NCM_NET_CLASS_KEY_UNAVAILABLE"
				break
			}
			valueGUID, _, err := k.GetStringValue("NetCfgInstanceId")
			k.Close()
			if err == nil {
				guid, ok = canonicalNetworkBinding(true, key, valueGUID)
			} else {
				ok = false
			}
			if !ok {
				r.Error = "NCM_INTERFACE_GUID_UNCONFIRMED"
				break
			}
		}
		set.Close()
		if r.Error == "" && !complete {
			r.Error = "NCM_MAPPING_ENUM_LIMIT"
		}
		if r.Error == "" && guid == "" {
			r.Error = "NCM_EXACT_NODE_ABSENT"
		}
		if r.Error == "" {
			r = readMappedAdapter(r, guid)
		}
		out = append(out, r)
	}
	return out
}

func readMappedAdapter(r NetworkAdapter, guid string) NetworkAdapter {
	size := uint32(15000)
	var buf []byte
	var e error
	for attempt := 0; attempt < 3; attempt++ {
		if size < 1 || size > 1<<20 {
			r.Error = "ADAPTER_BUFFER_SIZE_LIMIT"
			return r
		}
		buf = make([]byte, size)
		e = windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER|windows.GAA_FLAG_SKIP_FRIENDLY_NAME|windows.GAA_FLAG_INCLUDE_ALL_INTERFACES, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if e != windows.ERROR_BUFFER_OVERFLOW {
			break
		}
	}
	if e != nil {
		r.Error = "ADAPTER_ADDRESS_QUERY_" + eno(e)
		return r
	}
	defer runtime.KeepAlive(buf)
	base := uintptr(unsafe.Pointer(&buf[0]))
	end := base + uintptr(len(buf))
	inside := func(p unsafe.Pointer, n uintptr) bool { v := uintptr(p); return v >= base && v < end && n <= end-v }
	var match *windows.IpAdapterAddresses
	count := 0
	for a := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		count++
		if count > 1024 || !inside(unsafe.Pointer(a), unsafe.Sizeof(*a)) || uintptr(a.Length) < unsafe.Sizeof(*a) {
			r.Error = "ADAPTER_LIST_INVALID_OR_LIMIT"
			return r
		}
		// Other adapters can have short/non-GUID names. Ignore them without
		// reading beyond the returned buffer or exporting their identity.
		if !inside(unsafe.Pointer(a.AdapterName), 39) {
			continue
		}
		name := unsafe.Slice(a.AdapterName, 39)
		if name[38] != 0 || !strings.EqualFold(string(name[:38]), guid) {
			continue
		}
		if match != nil {
			r.Error = "NCM_ADAPTER_MATCH_AMBIGUOUS"
			return r
		}
		match = a
	}
	if match == nil {
		r.Error = "NCM_STARTED_NO_IP_ADAPTER_MATCH"
		return r
	}
	a := match
	r.Matched = true
	r.InterfaceIndex = a.IfIndex
	r.IPv6InterfaceIndex = a.Ipv6IfIndex
	r.OperStatus = a.OperStatus
	r.MTU = a.Mtu
	r.ReportedTransmitBPS = a.TransmitLinkSpeed
	r.ReportedReceiveBPS = a.ReceiveLinkSpeed
	count = 0
	for addr := a.FirstUnicastAddress; addr != nil; addr = addr.Next {
		count++
		if count > 128 || !inside(unsafe.Pointer(addr), unsafe.Sizeof(*addr)) || uintptr(addr.Length) < unsafe.Sizeof(*addr) {
			r.Error = "NCM_ADDRESS_LIST_INVALID_OR_LIMIT"
			return r
		}
		if addr.Address.Sockaddr == nil || addr.Address.SockaddrLength < 0 || !inside(unsafe.Pointer(addr.Address.Sockaddr), uintptr(addr.Address.SockaddrLength)) {
			r.Error = "NCM_ADDRESS_INVALID"
			return r
		}
		ip := addr.Address.IP()
		if ip != nil {
			r.Addresses = append(r.Addresses, NetworkAddress{ip.String(), addr.OnLinkPrefixLength, addr.DadState, addr.PrefixOrigin, addr.SuffixOrigin})
		}
	}
	row := windows.MibIfRow2{InterfaceLuid: a.Luid}
	if e = windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row); e != nil {
		r.Error = "NCM_STATISTICS_" + eno(e)
		return r
	}
	if row.InterfaceLuid != a.Luid || row.InterfaceIndex != a.IfIndex || !strings.EqualFold(row.InterfaceGuid.String(), guid) {
		r.Error = "NCM_INTERFACE_CHANGED_BEFORE_STATISTICS"
		return r
	}
	r.StatisticsRead = true
	r.OperStatus = row.OperStatus
	r.AdminStatus = row.AdminStatus
	r.InterfaceAndOperStatusFlags = row.InterfaceAndOperStatusFlags
	r.MediaConnectState = row.MediaConnectState
	r.MTU = row.Mtu
	r.InOctets = row.InOctets
	r.OutOctets = row.OutOctets
	r.InErrors = row.InErrors
	r.OutErrors = row.OutErrors
	r.InDiscards = row.InDiscards
	r.OutDiscards = row.OutDiscards
	if row.TransmitLinkSpeed != 0 {
		r.ReportedTransmitBPS = row.TransmitLinkSpeed
	}
	if row.ReceiveLinkSpeed != 0 {
		r.ReportedReceiveBPS = row.ReceiveLinkSpeed
	}
	r.luid = a.Luid
	r.key = fmt.Sprintf("%s/%d", guid, a.Luid)
	return r
}

// One passive snapshot while temporary grouping is applied. Readiness is
// proved by waitForPeerReady and runApplication; diagnostic sampling must not
// hold up address configuration for a fixed observation window.
// Own code sends no packets, alters no IP/firewall/routes and exports no other
// adapter's addresses, GUIDs, MACs, DNS or user-chosen network names.
func (b *groupingBackend) observeNetwork() NetworkObservation {
	done := RecordConnectionOperation("passive_network_observation")
	defer done()
	r := NetworkObservation{Status: "PASSIVE_OBSERVATION_COMPLETE_NOT_NETWORK_PROOF", PassiveOnly: true}
	start := time.Now()
	fresh := Inspect()
	sample := NetworkSample{ElapsedMS: time.Since(start).Milliseconds()}
	if !sameRootInstance(b.mode.Before, fresh) || !HasActiveNCM(fresh) {
		sample.Error = "NETWORK_OBSERVATION_TARGET_CHANGED_OR_NCM_LOST"
	} else {
		owned := false
		for _, n := range fresh.Nodes {
			if strings.EqualFold(n.instanceID, b.networkRoot()) && n.EnumeratorClass == "020000" && n.StateError == "" && n.Problem == 0 && !grouptrial.NeedsWindowsRestart(n.DevNodeStatus) {
				owned = true
			}
		}
		if !owned {
			sample.Error = "NETWORK_OBSERVATION_GROUPING_OR_ROOT_CHANGED"
		}
	}
	if sample.Error != "" {
		r.Samples = append(r.Samples, sample)
		r.Status = "TARGET_CHANGED_PASSIVE_OBSERVATION_STOPPED"
		return r
	}
	sample.TargetConfirmed = true
	sample.Adapters = readNCMAdapters(fresh)
	for _, a := range sample.Adapters {
		if a.Matched && a.Error == "" {
			recordConnectionStage("adapter_mapped", "exact_devnode_to_adapter_match")
		}
	}
	r.Samples = append(r.Samples, sample)
	return r
}
