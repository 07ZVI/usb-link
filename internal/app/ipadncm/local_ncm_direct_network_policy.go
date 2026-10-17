//go:build usblink_local_remote

package ipadncm

import (
	"strconv"
	"strings"
)

type directBindingEvidence struct {
	Source           string                `json:"source"`
	SampledUTC       string                `json:"sampled_utc,omitempty"`
	IDShape          string                `json:"id_shape"`
	RevisionVerified bool                  `json:"revision_matches_bound_descriptor"`
	DescriptorBCD    string                `json:"bound_descriptor_bcd,omitempty"`
	IDTokens         directIDTokenEvidence `json:"id_tokens"`
	Service          string                `json:"service"`
	INF              string                `json:"inf"`
	LowerCount       int                   `json:"lower_count"`
	UpperCount       int                   `json:"upper_count"`
	LowerKinds       [2]string             `json:"lower_kinds"`
	UpperKinds       [2]string             `json:"upper_kinds"`
	Failure          string                `json:"failure,omitempty"`
	NativeResult     string                `json:"native_result,omitempty"`
	NativeINF        string                `json:"native_inf,omitempty"`
	NativeProvider   string                `json:"native_provider,omitempty"`
}

type directIDTokenEvidence struct {
	Length         int       `json:"length"`
	USB            bool      `json:"usb"`
	Tokens         [5]string `json:"tokens"`
	Count          int       `json:"count"`
	Unknown        int       `json:"unknown"`
	Duplicates     int       `json:"duplicates"`
	Omitted        int       `json:"omitted"`
	InstanceSuffix bool      `json:"instance_suffix"`
	Truncated      bool      `json:"truncated"`
}

// This projection is diagnostic only. Export fixed keys and exact hex widths,
// preserving order, but never a third instance segment or unknown token text.
func directIDTokens(id string) directIDTokenEvidence {
	d := directIDTokenEvidence{Length: len(id)}
	if len(id) > 256 {
		d.Truncated = true
		return d
	}
	id = strings.ToUpper(id)
	if !strings.HasPrefix(id, `USB\`) {
		return d
	}
	d.USB = true
	body := id[4:]
	if i := strings.IndexByte(body, '\\'); i >= 0 {
		d.InstanceSuffix = true
		body = body[:i]
	}
	parts := strings.Split(body, "&")
	d.Count = len(parts)
	seen := map[string]bool{}
	for i, token := range parts {
		projected := "OTHER"
		for _, spec := range []struct {
			key   string
			width int
		}{{"VID", 4}, {"PID", 4}, {"REV", 4}, {"CDC", 2}, {"MI", 2}} {
			prefix := spec.key + "_"
			if strings.HasPrefix(token, prefix) && len(token) == len(prefix)+spec.width && strings.Trim(token[len(prefix):], "0123456789ABCDEF") == "" {
				projected = token
				if seen[spec.key] {
					d.Duplicates++
				}
				seen[spec.key] = true
				break
			}
		}
		if projected == "OTHER" {
			d.Unknown++
		}
		if i < len(d.Tokens) {
			d.Tokens[i] = projected
		} else {
			d.Omitted++
		}
	}
	return d
}

type directNetworkEvidence struct {
	NICSampled       bool   `json:"nic_sampled"`
	NICCount         int    `json:"nic_count"`
	Matched          bool   `json:"matched"`
	StatisticsRead   bool   `json:"statistics_read"`
	ReadError        bool   `json:"read_error"`
	OperStatus       uint32 `json:"oper_status"`
	AdminStatus      uint32 `json:"admin_status"`
	StatusFlags      uint8  `json:"interface_and_oper_status_flags"`
	MediaState       uint32 `json:"media_state"`
	InstanceMatched  bool   `json:"instance_matched"`
	ExpectedMatched  bool   `json:"expected_matched"`
	PeerStage        string `json:"peer_stage"`
	PeerStatus       string `json:"peer_status,omitempty"`
	NeighborCount    int    `json:"neighbor_count"`
	NeighborError    bool   `json:"neighbor_error"`
	EchoCount        int    `json:"echo_count"`
	ParsedEchoes     int    `json:"parsed_echoes"`
	NonceMatches     int    `json:"nonce_matches"`
	ScopedRoundtrips int    `json:"scoped_roundtrips"`
	IPv6Verified     bool   `json:"ipv6_verified"`
}

func directEvidenceCode(code string) string {
	if len(code) <= 96 && strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == "" {
		return code
	}
	return "OTHER"
}

func directEvidenceINF(inf string) string {
	if inf == "" {
		return "unavailable"
	}
	if len(inf) <= 64 && strings.Trim(inf, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") == "" && strings.HasSuffix(strings.ToLower(inf), ".inf") {
		return inf
	}
	return "other"
}

// Project only driver names and fixed identity categories, never an instance ID.
// Empty cached INF means unavailable; inventory does not distinguish read errors.
func directBindingProof(id, service, inf string, lower, upper []string, bcdDevice *uint16) directBindingEvidence {
	d := directBindingEvidence{Source: "cached_pnp_registry", IDShape: "other", Service: "other", INF: "other", LowerCount: len(lower), UpperCount: len(upper)}
	shape, revision, validID := directNCMInterfacePrefix(id)
	d.IDShape = shape
	d.IDTokens = directIDTokens(id)
	d.RevisionVerified = validID && shape != "exact_mi00" && bcdDevice != nil && revision == *bcdDevice
	if bcdDevice != nil {
		d.DescriptorBCD = strings.ToUpper(strconv.FormatUint(uint64(*bcdDevice), 16))
		d.DescriptorBCD = strings.Repeat("0", 4-len(d.DescriptorBCD)) + d.DescriptorBCD
	}
	if service == "" {
		d.Service = "unavailable"
	} else if strings.EqualFold(service, "UsbNcm") {
		d.Service = "UsbNcm"
	}
	d.INF = directEvidenceINF(inf)
	kinds := func(filters []string) (out [2]string) {
		for i, f := range filters {
			if i == len(out) {
				break
			}
			out[i] = "other"
			for _, known := range []string{"AppleLowerFilter", "WUDFRd", "usbscan"} {
				if strings.EqualFold(f, known) {
					out[i] = known
				}
			}
		}
		return
	}
	d.LowerKinds, d.UpperKinds = kinds(lower), kinds(upper)
	switch {
	case !validID:
		d.Failure = "DIRECT_NCM_ID_PREFIX_UNPROVEN"
	case shape != "exact_mi00" && !d.RevisionVerified:
		d.Failure = "DIRECT_NCM_REVISION_UNPROVEN"
	case !strings.EqualFold(service, "UsbNcm"):
		d.Failure = "DIRECT_NCM_SERVICE_BINDING_UNPROVEN"
	case !strings.EqualFold(inf, "usbncm.inf"):
		d.Failure = "DIRECT_NCM_CACHED_INF_UNPROVEN"
	case len(lower) != 0:
		d.Failure = "DIRECT_NCM_LOWER_FILTERS_PRESENT"
	case len(upper) != 0:
		d.Failure = "DIRECT_NCM_UPPER_FILTERS_PRESENT"
	}
	return d
}

func directNCMInterfacePrefix(id string) (shape string, revision uint16, valid bool) {
	for i := range len(id) {
		if id[i] > 0x7f {
			return "other", 0, false
		}
	}
	id = strings.ToUpper(id)
	if id == `USB\VID_05AC&PID_12AB&MI_00` {
		return "exact_mi00", 0, true
	}
	const prefix = `USB\VID_05AC&PID_12AB&REV_`
	suffix, shape := "&MI_00", "revision_mi00"
	// CDC_0D names the master subclass of the already-verified Direct control
	// interface 0. Other collections cannot borrow this target's admission.
	if len(id) == len(prefix)+4+len("&CDC_0D&MI_00") {
		suffix, shape = "&CDC_0D&MI_00", "revision_cdc0d_mi00"
	}
	if len(id) != len(prefix)+4+len(suffix) || !strings.HasPrefix(id, prefix) || !strings.HasSuffix(id, suffix) {
		return "other", 0, false
	}
	hex := id[len(prefix) : len(prefix)+4]
	if strings.Trim(hex, "0123456789ABCDEF") != "" {
		return "other", 0, false
	}
	v, err := strconv.ParseUint(hex, 16, 16)
	return shape, uint16(v), err == nil
}

func directIPv4Ready(dhcpACKs uint32, peerVerified bool, problem string) bool {
	return dhcpACKs > 0 && peerVerified && problem == ""
}

// Admit only the measured Direct topology, separately from the public cfg5
// dual-NCM preflight. These descriptors do not prove IP or peer readiness.
func directNetworkTopology(configs []Configuration, current byte) bool {
	if !directOnlyNCMLayout(configs, current) {
		return false
	}
	c := configs[0]
	if len(c.Interfaces) != 3 || len(c.Associations) != 0 {
		return false
	}
	control, empty, data := false, false, false
	for _, i := range c.Interfaces {
		switch {
		case i.Number == 0 && i.Alternate == 0 && i.Class == 2 && i.Subclass == 13 && i.Protocol == 0:
			if control || len(i.Endpoints) != 1 || i.Endpoints[0] != (Endpoint{Address: 0x81, Type: 3, MaxPacket: 16}) || len(i.Slaves) != 1 || i.Slaves[0] != 1 || len(i.Functions) != 3 {
				return false
			}
			header, ethernet, ncm := false, false, false
			for _, f := range i.Functions {
				switch f.Subtype {
				case 0:
					if header || f.Length != 5 || f.Version == nil || *f.Version != 0x110 {
						return false
					}
					header = true
				case 15:
					if ethernet || f.Length != 13 || f.MaxSegment == nil || *f.MaxSegment < 1514 {
						return false
					}
					ethernet = true
				case 26:
					if ncm || f.Length != 6 || f.Version == nil || *f.Version != 0x100 || f.Capabilities == nil {
						return false
					}
					ncm = true
				default:
					return false
				}
			}
			control = header && ethernet && ncm
		case i.Number == 1 && i.Alternate == 0 && i.Class == 10 && i.Subclass == 0 && i.Protocol == 1:
			if empty || len(i.Endpoints) != 0 || len(i.Slaves) != 0 || len(i.Functions) != 0 {
				return false
			}
			empty = true
		case i.Number == 1 && i.Alternate == 1 && i.Class == 10 && i.Subclass == 0 && i.Protocol == 1:
			if data || len(i.Endpoints) != 2 || len(i.Slaves) != 0 || len(i.Functions) != 0 {
				return false
			}
			in, out := false, false
			for _, e := range i.Endpoints {
				if e.Type != 2 || (e.MaxPacket != 64 && e.MaxPacket != 512 && e.MaxPacket != 1024) {
					return false
				}
				switch e.Address {
				case 0x82:
					if in {
						return false
					}
					in = true
				case 1:
					if out {
						return false
					}
					out = true
				default:
					return false
				}
			}
			data = in && out
		default:
			return false
		}
	}
	return control && empty && data
}
