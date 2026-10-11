package ipadncm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const softwareReconnectReceiptName = "ipad-software-reconnect.json"
const softwareReconnectReceiptLimit = 16384

type softwareReconnectJournal struct {
	Version        int      `json:"version"`
	StartedUTC     string   `json:"started_utc"`
	RootID         string   `json:"root_instance_id"`
	HardwarePrefix string   `json:"hardware_prefix"`
	Class          string   `json:"class_guid"`
	Service        string   `json:"service"`
	Hub            string   `json:"physical_hub"`
	Port           uint32   `json:"physical_port"`
	ParentID       string   `json:"native_parent_instance_id"`
	LocationPaths  []string `json:"physical_location_paths"`
	Configuration  byte     `json:"original_usb_configuration"`
	Product        string   `json:"usb_product"`
	Status         uint32   `json:"original_cm_status"`
	Problem        uint32   `json:"original_cm_problem"`
	ConfigFlags    uint32   `json:"original_config_flags"`
	FlagsPresent   bool     `json:"original_config_flags_present"`
}

func (j softwareReconnectJournal) valid() bool {
	target := softwareReconnectTarget{RootID: j.RootID, HardwarePrefix: j.HardwarePrefix, Class: j.Class, Service: j.Service, Status: j.Status, Problem: j.Problem, ConfigFlags: j.ConfigFlags, AuthorizedFixedAction: true, CurrentLauncherIdentity: true, ExactPhysicalRoot: true, StateAndPropertiesReadable: true, CleanupVerified: true}
	if j.Version != 1 || (!j.FlagsPresent && j.ConfigFlags != 0) || !target.eligible() || j.Port == 0 || j.Port > 127 || len(j.Hub) > 4096 || !strings.HasPrefix(strings.ToUpper(j.Hub), `\\?\USB#`) || len(j.ParentID) < 8 || len(j.ParentID) > 1024 || len(j.LocationPaths) < 1 || len(j.LocationPaths) > 4 || j.Product == "" || len(j.Product) > 256 || (j.Configuration != 3 && j.Configuration != 5) {
		return false
	}
	if _, e := time.Parse(time.RFC3339Nano, j.StartedUTC); e != nil {
		return false
	}
	for _, s := range append([]string{j.RootID, j.ParentID, j.Hub, j.Product}, j.LocationPaths...) {
		if s == "" || len(s) > 4096 || strings.ContainsAny(s, "\x00\r\n") {
			return false
		}
	}
	return true
}
func decodeSoftwareReconnectJournal(b []byte) (softwareReconnectJournal, error) {
	var j softwareReconnectJournal
	if len(b) == 0 || len(b) > softwareReconnectReceiptLimit {
		return j, fmt.Errorf("software reconnect receipt size invalid")
	}
	if !softwareReceiptUniqueKeys(b) {
		return j, fmt.Errorf("software reconnect receipt duplicate/invalid fields")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var tail any
	if d.Decode(&j) != nil || d.Decode(&tail) != io.EOF || !j.valid() {
		return j, fmt.Errorf("software reconnect receipt invalid")
	}
	return j, nil
}

type SoftwareReconnectNativeObservation struct {
	ExactInstance     bool   `json:"exact_instance"`
	ExactClass        bool   `json:"exact_class"`
	ExactService      bool   `json:"exact_service"`
	HubParentMatches  bool   `json:"native_parent_matches_physical_hub"`
	HubInstanceCR     uint32 `json:"hub_instance_cr"`
	ExactParent       bool   `json:"exact_parent"`
	ExactLocation     bool   `json:"exact_location"`
	ExactPhysicalPort bool   `json:"exact_physical_port"`
	UniqueRoot        bool   `json:"unique_native_root"`
	StateReadable     bool   `json:"cm_state_readable"`
	FlagsPresent      bool   `json:"cm_flags_present"`
	FlagsReadable     bool   `json:"cm_flags_readable"`
	Status            uint32 `json:"cm_status"`
	Problem           uint32 `json:"cm_problem"`
	ConfigFlags       uint32 `json:"cm_config_flags"`
	LocateCR          uint32 `json:"locate_cr"`
	StateCR           uint32 `json:"state_cr"`
	FlagsCR           uint32 `json:"flags_cr"`
	InstanceCR        uint32 `json:"instance_cr"`
	ClassCR           uint32 `json:"class_cr"`
	CMClassGUID       string `json:"cm_class_guid"`
	ClassPropertyType uint32 `json:"cm_class_property_type"`
	ClassPropertySize uint32 `json:"cm_class_property_size"`
	SetupClassGUID    string `json:"setupdi_class_guid"`
	ExpectedClassGUID string `json:"expected_class_guid"`
	ServiceCR         uint32 `json:"service_cr"`
	ParentCR          uint32 `json:"parent_cr"`
	Error             string `json:"error,omitempty"`
}

func (s SoftwareReconnectNativeObservation) owned(j softwareReconnectJournal) bool {
	return j.valid() && s.ExactInstance && s.ExactClass && s.ExactService && s.ExactParent && s.HubParentMatches && s.ExactLocation && s.ExactPhysicalPort && s.UniqueRoot && s.StateReadable && s.FlagsReadable && s.ConfigFlags == j.ConfigFlags && s.FlagsPresent == j.FlagsPresent && s.Status&(0x100|0x40000) == 0
}
func (s SoftwareReconnectNativeObservation) enabled(j softwareReconnectJournal) bool {
	return s.owned(j) && s.Problem == j.Problem && s.Status&8 != 0 && s.Status&0x400 == 0
}
func (s SoftwareReconnectNativeObservation) disabled(j softwareReconnectJournal) bool {
	return s.owned(j) && s.Problem == 22 && s.Status&8 == 0 && s.Status&0x400 != 0
}

func softwareReceiptUniqueKeys(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	start, e := d.Token()
	if e != nil || start != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return false
		}
		k, ok := key.(string)
		if !ok || seen[k] {
			return false
		}
		seen[k] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	for _, k := range []string{"version", "started_utc", "root_instance_id", "hardware_prefix", "class_guid", "service", "physical_hub", "physical_port", "native_parent_instance_id", "physical_location_paths", "original_usb_configuration", "usb_product", "original_cm_status", "original_cm_problem", "original_config_flags", "original_config_flags_present"} {
		if !seen[k] {
			return false
		}
	}
	end, e := d.Token()
	return e == nil && end == json.Delim('}')
}
