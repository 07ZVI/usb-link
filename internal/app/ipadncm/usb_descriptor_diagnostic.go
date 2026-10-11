package ipadncm

import (
	"strings"
	"sync"
	"time"
)

type USBDescriptorRecheckDiagnostic struct {
	QueryDurationMS          int64                          `json:"query_duration_ms"`
	ConnectionReadErrors     int                            `json:"connection_info_read_errors"`
	ConnectionNotPresent     int                            `json:"connection_info_not_present_samples"`
	ConnectionReadErrorCodes []string                       `json:"connection_info_read_error_codes,omitempty"`
	Phase                    string                         `json:"phase"`
	InventoryError           string                         `json:"inventory_error,omitempty"`
	HubsScanned              int                            `json:"hubs_scanned"`
	HubErrors                int                            `json:"hub_errors"`
	DeviceCount              int                            `json:"apple_mobile_devices_observed"`
	IdentityVerified         bool                           `json:"serial_product_native_binding_verified"`
	ProductReadStatus        string                         `json:"product_read_status,omitempty"`
	SerialReadStatus         string                         `json:"serial_read_status,omitempty"`
	SerialFailureShape       *USBIdentityStringFailureShape `json:"serial_failure_shape,omitempty"`
	RejectionCodes           []string                       `json:"rejection_codes,omitempty"`
	SameRoot                 bool                           `json:"same_root_not_authorization"`
	ActiveNCM                bool                           `json:"active_ncm_not_authorization"`
	OwnOperationCorrelation  string                         `json:"own_operation_time_correlation_not_causal_proof,omitempty"`
}

var usbDescriptorRecheckHistory struct {
	sync.Mutex
	recent []USBDescriptorRecheckDiagnostic
}

func boundedUSBRejectionCode(s string) string {
	known := s == "" || s == "TIME_LIMIT" || s == "API_FAILED" || s == "application_watch_baseline" || s == "application_device_event" || s == "explicit_readonly"
	for _, prefix := range []string{"USB_", "CONFIG_", "HUB_", "WIN32_", "CM_", "CONNECTION_"} {
		known = known || strings.HasPrefix(s, prefix)
	}
	for _, op := range []string{"grouping_write", "device_restart", "grouping_restore", "apple_service_lease", "passive_network_observation", "native_start_check", "application_firewall", "core_permissions", "sunshine_local_probe", "application_permission_batch"} {
		known = known || s == op
	}
	if !known || len(s) > 96 {
		return "UNKNOWN_OR_UNBOUNDED_REJECTION"
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return "UNKNOWN_OR_UNBOUNDED_REJECTION"
		}
	}
	return s
}
func sanitizeUSBDescriptorRecheck(d USBDescriptorRecheckDiagnostic) USBDescriptorRecheckDiagnostic {
	d.Phase = boundedUSBRejectionCode(d.Phase)
	d.InventoryError = boundedUSBRejectionCode(d.InventoryError)
	d.ProductReadStatus = boundedUSBRejectionCode(d.ProductReadStatus)
	d.SerialReadStatus = boundedUSBRejectionCode(d.SerialReadStatus)
	if len(d.RejectionCodes) > 16 {
		d.RejectionCodes = d.RejectionCodes[:16]
	}
	d.RejectionCodes = append([]string(nil), d.RejectionCodes...)
	for i := range d.RejectionCodes {
		d.RejectionCodes[i] = boundedUSBRejectionCode(d.RejectionCodes[i])
	}
	if len(d.ConnectionReadErrorCodes) > 16 {
		d.ConnectionReadErrorCodes = d.ConnectionReadErrorCodes[:16]
	}
	d.ConnectionReadErrorCodes = append([]string(nil), d.ConnectionReadErrorCodes...)
	for i := range d.ConnectionReadErrorCodes {
		d.ConnectionReadErrorCodes[i] = boundedUSBRejectionCode(d.ConnectionReadErrorCodes[i])
	}
	d.OwnOperationCorrelation = boundedUSBRejectionCode(d.OwnOperationCorrelation)
	if d.SerialFailureShape != nil {
		x := *d.SerialFailureShape
		d.SerialFailureShape = &x
	}
	return d
}
func recordUSBDescriptorRecheck(d USBDescriptorRecheckDiagnostic) {
	d = sanitizeUSBDescriptorRecheck(d)
	usbDescriptorRecheckHistory.Lock()
	defer usbDescriptorRecheckHistory.Unlock()
	if len(usbDescriptorRecheckHistory.recent) == 8 {
		copy(usbDescriptorRecheckHistory.recent, usbDescriptorRecheckHistory.recent[1:])
		usbDescriptorRecheckHistory.recent = usbDescriptorRecheckHistory.recent[:7]
	}
	usbDescriptorRecheckHistory.recent = append(usbDescriptorRecheckHistory.recent, d)
}
func USBDescriptorRecheckDiagnostics() []USBDescriptorRecheckDiagnostic {
	usbDescriptorRecheckHistory.Lock()
	defer usbDescriptorRecheckHistory.Unlock()
	r := append([]USBDescriptorRecheckDiagnostic(nil), usbDescriptorRecheckHistory.recent...)
	for i := range r {
		r[i].RejectionCodes = append([]string(nil), r[i].RejectionCodes...)
		r[i].ConnectionReadErrorCodes = append([]string(nil), r[i].ConnectionReadErrorCodes...)
		if r[i].SerialFailureShape != nil {
			x := *r[i].SerialFailureShape
			r[i].SerialFailureShape = &x
		}
	}
	return r
}

func descriptorOwnOperationCorrelation() string {
	monitorDiagnostics.Lock()
	defer monitorDiagnostics.Unlock()
	if monitorDiagnostics.deviceKind == "iPad" && (monitorDiagnostics.operationActive || time.Since(monitorDiagnostics.operationAt) <= 2*time.Second) {
		return boundedUSBRejectionCode(monitorDiagnostics.operation)
	}
	return ""
}
