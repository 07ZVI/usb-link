package netconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"suhang/usbnet/internal/transport/usbaddress"
)

// HostIdentityDiagnostic is a one-shot observation, never an authorization or
// recovery proof. Null means the corresponding provider query did not finish.
// Neither the PnP instance nor any provider exception text is exported.
type HostIdentityDiagnostic struct {
	NativeReadback       bool                          `json:"native_readback,omitempty"`
	ServiceType          uint32                        `json:"service_type,omitempty"`
	ServiceSize          uint32                        `json:"service_size,omitempty"`
	ClassType            uint32                        `json:"class_type,omitempty"`
	ClassSize            uint32                        `json:"class_size,omitempty"`
	Phase                string                        `json:"phase"`
	HResult              int64                         `json:"hresult"`
	AdapterCount         *int                          `json:"adapter_count"`
	GUIDMatches          *bool                         `json:"guid_matches"`
	AliasMatches         *bool                         `json:"alias_matches"`
	IndexMatches         *bool                         `json:"index_matches"`
	InstanceNonempty     *bool                         `json:"instance_nonempty"`
	InstanceWildcardFree *bool                         `json:"instance_wildcard_free"`
	PnPCount             *int                          `json:"pnp_count"`
	ServiceWintun        *bool                         `json:"service_wintun"`
	ClassNet             *bool                         `json:"class_net"`
	QueryError           string                        `json:"query_error,omitempty"`
	InstalledNodes       *HostInstalledNodeObservation `json:"installed_nodes,omitempty"`
}

// Installed-node observations deliberately have no device instance or registry
// path. They never bypass the present, healthy-node recovery proof.
type HostInstalledNodeObservation struct {
	ObservationOnly     bool                                `json:"observation_only"`
	Complete            bool                                `json:"complete"`
	Enumerated          int                                 `json:"enumerated"`
	MissingDriverKeys   int                                 `json:"missing_driver_keys"`
	MissingNetworkGUIDs int                                 `json:"missing_network_guids"`
	ForeignNetworkGUIDs int                                 `json:"foreign_network_guids"`
	BindingMatches      int                                 `json:"binding_matches"`
	Candidates          []HostInstalledCandidateObservation `json:"candidates,omitempty"`
	CandidatesTruncated bool                                `json:"candidates_truncated,omitempty"`
	QueryError          string                              `json:"query_error,omitempty"`
}

type HostInstalledCandidateObservation struct {
	IdentityValid        bool    `json:"identity_valid"`
	IdentityError        string  `json:"identity_error,omitempty"`
	StateReadable        bool    `json:"state_readable"`
	StateError           uint32  `json:"state_error,omitempty"`
	Status               uint32  `json:"status"`
	Problem              uint32  `json:"problem"`
	InstallFlagsReadable bool    `json:"install_flags_readable"`
	RestartRequired      bool    `json:"restart_required"`
	NormalResult         *uint32 `json:"normal_lookup_result,omitempty"`
	PhantomResult        *uint32 `json:"phantom_lookup_result,omitempty"`
	PhantomExact         *bool   `json:"phantom_exact,omitempty"`
	ConfigReadable       *bool   `json:"config_readable,omitempty"`
	ConfigType           *uint32 `json:"config_type,omitempty"`
	ConfigSize           *uint32 `json:"config_size,omitempty"`
	ConfigValue          *uint32 `json:"config_value,omitempty"`
	CMConfigReadable     *bool   `json:"cm_config_readable,omitempty"`
	CMConfigType         *uint32 `json:"cm_config_type,omitempty"`
	CMConfigSize         *uint32 `json:"cm_config_size,omitempty"`
	CMConfigValue        *uint32 `json:"cm_config_value,omitempty"`
	NonpresentProofError string  `json:"nonpresent_proof_error,omitempty"`
}

func sharedHostIdentityDiagnosticScript(index uint32) string {
	return fmt.Sprintf(`$ErrorActionPreference='Stop';
$d=[ordered]@{phase='adapter_query';hresult=0;adapter_count=$null;guid_matches=$null;alias_matches=$null;index_matches=$null;instance_nonempty=$null;instance_wildcard_free=$null;pnp_count=$null;service_wintun=$null;class_net=$null};
try {
 $a=@(Get-NetAdapter -IncludeHidden | Where-Object {[guid]$_.InterfaceGuid -eq [guid]'%s' -or $_.Name -ceq 'USB Link Host'});
 $d.adapter_count=$a.Count; $d.phase='adapter_mapping';
 if($a.Count -eq 1) {
  $d.guid_matches=([guid]$a[0].InterfaceGuid -eq [guid]'%s'); $d.alias_matches=($a[0].Name -ceq 'USB Link Host'); $d.index_matches=([uint32]$a[0].ifIndex -eq %d);
  $id=[string]$a[0].PnPDeviceID; $d.instance_nonempty=(-not [string]::IsNullOrWhiteSpace($id)); $d.instance_wildcard_free=(-not ($id.Contains('*') -or $id.Contains('?')));
  $d.phase='pnp_instance';
  if($d.guid_matches -and $d.alias_matches -and $d.index_matches -and $d.instance_nonempty -and $d.instance_wildcard_free) {
   $d.phase='pnp_query'; $p=@(Get-CimInstance -ClassName Win32_PnPEntity | Where-Object {$_.DeviceID -ieq $id}); $d.pnp_count=$p.Count; $d.phase='pnp_identity';
   if($p.Count -eq 1) { $d.service_wintun=($p[0].Service -ieq 'Wintun'); $d.class_net=([string]$p[0].ClassGuid -ieq '{4d36e972-e325-11ce-bfc1-08002be10318}'); }
  }
 }
} catch { $d.hresult=[int64]$_.Exception.HResult; }
$d | ConvertTo-Json -Compress`, usbaddress.HostGUID, usbaddress.HostGUID, index)
}

func decodeHostIdentityDiagnostic(b []byte) (HostIdentityDiagnostic, error) {
	var d HostIdentityDiagnostic
	if len(b) > 4096 {
		return d, fmt.Errorf("USB_HOST_DIAGNOSTIC_OUTPUT_INVALID")
	}
	// Require explicit nulls for unavailable observations. Missing or duplicate
	// fields must not look like a provider query completed with unknown values.
	required := map[string]bool{"phase": false, "hresult": false, "adapter_count": false, "guid_matches": false, "alias_matches": false, "index_matches": false, "instance_nonempty": false, "instance_wildcard_free": false, "pnp_count": false, "service_wintun": false, "class_net": false}
	fields := json.NewDecoder(bytes.NewReader(b))
	start, e := fields.Token()
	if e != nil || start != json.Delim('{') {
		return HostIdentityDiagnostic{}, fmt.Errorf("USB_HOST_DIAGNOSTIC_OUTPUT_INVALID")
	}
	for fields.More() {
		key, e := fields.Token()
		name, ok := key.(string)
		seen, known := required[name]
		if e != nil || !ok || !known || seen {
			return HostIdentityDiagnostic{}, fmt.Errorf("USB_HOST_DIAGNOSTIC_OUTPUT_INVALID")
		}
		required[name] = true
		var value json.RawMessage
		if fields.Decode(&value) != nil {
			return HostIdentityDiagnostic{}, fmt.Errorf("USB_HOST_DIAGNOSTIC_OUTPUT_INVALID")
		}
	}
	for _, seen := range required {
		if !seen {
			return HostIdentityDiagnostic{}, fmt.Errorf("USB_HOST_DIAGNOSTIC_OUTPUT_INVALID")
		}
	}
	r := json.NewDecoder(bytes.NewReader(b))
	r.DisallowUnknownFields()
	if r.Decode(&d) != nil || r.Decode(new(any)) != io.EOF {
		return HostIdentityDiagnostic{}, fmt.Errorf("USB_HOST_DIAGNOSTIC_OUTPUT_INVALID")
	}
	switch d.Phase {
	case "adapter_query", "adapter_mapping", "pnp_instance", "pnp_query", "pnp_identity":
	default:
		return HostIdentityDiagnostic{}, fmt.Errorf("USB_HOST_DIAGNOSTIC_OUTPUT_INVALID")
	}
	if d.QueryError != "" || d.HResult < -2147483648 || d.HResult > 2147483647 || d.AdapterCount != nil && (*d.AdapterCount < 0 || *d.AdapterCount > 65536) || d.PnPCount != nil && (*d.PnPCount < 0 || *d.PnPCount > 65536) {
		return HostIdentityDiagnostic{}, fmt.Errorf("USB_HOST_DIAGNOSTIC_OUTPUT_INVALID")
	}
	return d, nil
}
