package ipadncm

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"howett.net/plist"
)

// Export only counts and fixed protocol results, never identifiers or raw plists.
type MuxDiagnostic struct {
	ListArrayPresent   bool    `json:"list_array_present"`
	ListResult         *uint64 `json:"list_result_code,omitempty"`
	ListedEntries      int     `json:"listed_entries"`
	ListenAttempted    bool    `json:"listen_attempted"`
	ListenAccepted     bool    `json:"listen_accepted"`
	ListenResult       *uint64 `json:"listen_result_code,omitempty"`
	USBEntries         int     `json:"usb_entries"`
	NetworkEntries     int     `json:"network_entries"`
	UnknownEntries     int     `json:"unknown_entries"`
	EmptyListWait      bool    `json:"empty_list_read_only_wait_attempted"`
	ListenWindowMS     int64   `json:"listen_observation_window_ms,omitempty"`
	ListenElapsedMS    int64   `json:"listen_observed_elapsed_ms,omitempty"`
	CommunicationState string  `json:"communication_state,omitempty"`
	TrustState         string  `json:"pairing_or_trust_observation,omitempty"`
	DeviceErrorClass   string  `json:"device_error_class,omitempty"`
}

const emptyMuxListWait = 8 * time.Second

func queryDeadline(ctx context.Context, d time.Duration) time.Time {
	end := time.Now().Add(d)
	if limit, ok := ctx.Deadline(); ok && limit.Before(end) {
		end = limit
	}
	return end
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func sendMux(c net.Conn, m map[string]any) error {
	b, e := plist.Marshal(m, plist.XMLFormat)
	if e != nil {
		return e
	}
	h := make([]byte, 16)
	binary.LittleEndian.PutUint32(h, uint32(16+len(b)))
	binary.LittleEndian.PutUint32(h[4:], 1)
	binary.LittleEndian.PutUint32(h[8:], 8)
	binary.LittleEndian.PutUint32(h[12:], 1)
	if e = writeAll(c, h); e != nil {
		return e
	}
	return writeAll(c, b)
}
func receiveMux(c net.Conn, event bool) (map[string]any, error) {
	h := make([]byte, 16)
	if n, e := io.ReadFull(c, h); e != nil {
		if n > 0 {
			return nil, fmt.Errorf("partial mux header: %w", e)
		}
		return nil, e
	}
	n := binary.LittleEndian.Uint32(h)
	tag := binary.LittleEndian.Uint32(h[12:])
	if n < 17 || n > 512*1024+16 || binary.LittleEndian.Uint32(h[4:]) != 1 || binary.LittleEndian.Uint32(h[8:]) != 8 || (!event && tag != 1) || (event && tag > 1) {
		return nil, fmt.Errorf("invalid mux frame")
	}
	b := make([]byte, n-16)
	if _, e := io.ReadFull(c, b); e != nil {
		return nil, fmt.Errorf("partial mux payload: %w", e)
	}
	var m map[string]any
	_, e := plist.Unmarshal(b, &m)
	return m, e
}
func muxMessage(name string) map[string]any {
	return map[string]any{"MessageType": name, "ClientVersionString": "Suhang-NCM-Check", "ProgName": "Suhang-NCM-Check", "kLibUSBMuxVersion": uint64(3)}
}

func queryModel(ctx context.Context, address string, diag *MuxDiagnostic) (string, string, string) {
	return queryModelWithEmptyWait(ctx, address, diag, emptyMuxListWait)
}

func queryModelWithEmptyWait(ctx context.Context, address string, diag *MuxDiagnostic, emptyWait time.Duration) (string, string, string) {
	if emptyWait <= 0 || emptyWait > emptyMuxListWait {
		return "", "", "APPLE_USB_OBSERVATION_LIMIT_INVALID"
	}
	diag.CommunicationState = "QUERY_STARTED"
	diag.TrustState = "UNKNOWN_NOT_AUTHENTICATED"
	// A user ending the monitor must also interrupt a read-only subscription.
	var stops []func() bool
	defer func() {
		for _, stop := range stops {
			stop()
		}
	}()
	dial := func() (net.Conn, error) {
		c, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", address)
		if e == nil {
			stops = append(stops, context.AfterFunc(ctx, func() { c.Close() }))
		}
		return c, e
	}
	c, e := dial()
	if e != nil {
		diag.CommunicationState = "SERVICE_TRANSPORT_UNAVAILABLE"
		return "", "", "APPLE_USB_SERVICE_UNAVAILABLE"
	}
	c.SetDeadline(queryDeadline(ctx, 3*time.Second))
	e = sendMux(c, muxMessage("ListDevices"))
	var response map[string]any
	if e == nil {
		response, e = receiveMux(c, false)
	}
	c.Close()
	devices := map[uint64]map[string]any{}
	add := func(entry map[string]any) {
		p, ok := entry["Properties"].(map[string]any)
		if !ok {
			diag.UnknownEntries++
			return
		}
		// Upstream usbmuxd places the handle in Properties for Attached and
		// ListDevices. Also accept the enclosing handle used by some versions.
		id, _ := p["DeviceID"].(uint64)
		if id == 0 {
			id, _ = entry["DeviceID"].(uint64)
		}
		if id == 0 {
			diag.UnknownEntries++
			return
		}
		devices[id] = p
	}
	if result, ok := response["Number"].(uint64); ok {
		diag.ListResult = &result
	}
	listSupported := false
	if list, ok := response["DeviceList"].([]any); e == nil && ok {
		listSupported = true
		diag.ListArrayPresent = true
		diag.ListedEntries = len(list)
		if len(list) > 64 {
			return "", "", "APPLE_USB_DEVICE_LIST_TOO_LARGE"
		}
		for _, v := range list {
			entry, ok := v.(map[string]any)
			if !ok {
				diag.UnknownEntries++
				continue
			}
			add(entry)
		}
	}
	if !listSupported || diag.ListedEntries == 0 {
		// Windows/older services may not support ListDevices. Listen is a
		// read-only subscription; collect initial Attached notifications.
		diag.ListenAttempted = true
		diag.EmptyListWait = listSupported && diag.ListedEntries == 0
		c, e = dial()
		if e != nil {
			return "", "", "APPLE_USB_LISTEN_TRANSPORT_UNAVAILABLE"
		}
		c.SetDeadline(queryDeadline(ctx, 3*time.Second))
		response = nil
		e = sendMux(c, muxMessage("Listen"))
		if e == nil {
			response, e = receiveMux(c, false)
		}
		if result, ok := response["Number"].(uint64); ok {
			diag.ListenResult = &result
		}
		if e != nil || response["MessageType"] != "Result" || response["Number"] != uint64(0) {
			c.Close()
			return "", "", "APPLE_USB_LISTEN_NOT_ACCEPTED"
		}
		diag.ListenAccepted = true
		// Fixed observation window: a timeout in a partial frame is not an
		// empty-device result, and the socket is never reused after a timeout.
		window := 2 * time.Second
		if diag.EmptyListWait {
			window = emptyWait
		}
		diag.ListenWindowMS = window.Milliseconds()
		observedAt := time.Now()
		observationComplete := false
		defer func() {
			if !observationComplete {
				diag.ListenElapsedMS = time.Since(observedAt).Milliseconds()
			}
		}()
		c.SetDeadline(queryDeadline(ctx, window))
		for i := 0; i < 64; i++ {
			response, e = receiveMux(c, true)
			if e != nil {
				if ctx.Err() != nil {
					c.Close()
					return "", "", "APPLE_USB_QUERY_CANCELLED_OR_TIMED_OUT"
				}
				if ne, ok := e.(net.Error); ok && ne.Timeout() {
					break
				}
				c.Close()
				return "", "", "APPLE_USB_LISTEN_READ_FAILED"
			}
			switch response["MessageType"] {
			case "Attached":
				add(response)
			case "Detached":
				id, _ := response["DeviceID"].(uint64)
				delete(devices, id)
			}
			if i == 63 {
				c.Close()
				return "", "", "APPLE_USB_LISTEN_EVENT_LIMIT"
			}
		}
		c.Close()
		diag.ListenElapsedMS = time.Since(observedAt).Milliseconds()
		observationComplete = true
	}
	var id uint64
	for handle, p := range devices {
		switch p["ConnectionType"] {
		case "USB":
			diag.USBEntries++
			id = handle
		case "Network":
			diag.NetworkEntries++
		default:
			diag.UnknownEntries++
		}
	}
	if diag.USBEntries != 1 || diag.UnknownEntries != 0 || id == 0 {
		diag.CommunicationState = "USB_DEVICE_ABSENT_OR_AMBIGUOUS"
		if diag.EmptyListWait && len(devices) == 0 && diag.UnknownEntries == 0 {
			diag.TrustState = "UNKNOWN_NO_USB_COMMUNICATION_DEVICE"
			return "", "", "APPLE_USB_DEVICE_NOT_READY"
		}
		return "", "", "NEED_ONE_USB_APPLE_COMMUNICATION_DEVICE"
	}
	diag.CommunicationState = "ONE_USB_COMMUNICATION_DEVICE"
	c, e = dial()
	if e != nil {
		return "", "", "LOCKDOWN_TRANSPORT_UNAVAILABLE"
	}
	defer c.Close()
	c.SetDeadline(queryDeadline(ctx, 3*time.Second))
	m := muxMessage("Connect")
	m["DeviceID"] = id
	m["PortNumber"] = uint64(0x7ef2)
	e = sendMux(c, m)
	if e == nil {
		response, e = receiveMux(c, false)
	}
	if e != nil || response["MessageType"] != "Result" || response["Number"] != uint64(0) {
		return "", "", "LOCKDOWN_CONNECT_FAILED"
	}
	var out [2]string
	for i, key := range []string{"ProductType", "ProductVersion"} {
		c.SetDeadline(queryDeadline(ctx, 3*time.Second))
		b, err := plist.Marshal(map[string]any{"Request": "GetValue", "Key": key, "Label": "Suhang-NCM-Check"}, plist.XMLFormat)
		if err != nil {
			return "", "", "PRODUCT_METADATA_QUERY_FAILED"
		}
		h := make([]byte, 4)
		binary.BigEndian.PutUint32(h, uint32(len(b)))
		if writeAll(c, h) != nil || writeAll(c, b) != nil {
			return "", "", "PRODUCT_METADATA_QUERY_FAILED"
		}
		if _, err = io.ReadFull(c, h); err != nil {
			return "", "", "PRODUCT_METADATA_QUERY_FAILED"
		}
		n := binary.BigEndian.Uint32(h)
		if n == 0 || n > 512*1024 {
			return "", "", "PRODUCT_METADATA_QUERY_FAILED"
		}
		b = make([]byte, n)
		if _, err = io.ReadFull(c, b); err != nil {
			return "", "", "PRODUCT_METADATA_QUERY_FAILED"
		}
		var answer map[string]any
		if _, err = plist.Unmarshal(b, &answer); err != nil {
			return "", "", "PRODUCT_METADATA_QUERY_FAILED"
		}
		if code, ok := answer["Error"].(string); ok {
			diag.DeviceErrorClass, diag.TrustState = classifyMetadataDeviceError(code)
			return "", "", "PRODUCT_METADATA_DEVICE_REJECTED"
		}
		out[i], _ = answer["Value"].(string)
		if out[i] == "" || len(out[i]) > 64 {
			return "", "", "PRODUCT_METADATA_MISSING_OR_INVALID"
		}
	}
	diag.CommunicationState = "USB_PRODUCT_METADATA_RECEIVED_NOT_PAIRING_PROOF"
	return out[0], out[1], ""
}

func classifyMetadataDeviceError(code string) (string, string) {
	switch code {
	case "PairingDialogResponsePending":
		return "PAIRING_RESPONSE_PENDING", "DEVICE_REPORTS_PAIRING_PENDING"
	case "UserDeniedPairing":
		return "PAIRING_DENIED", "DEVICE_REPORTS_PAIRING_DENIED"
	case "PasswordProtected":
		return "DEVICE_LOCKED", "DEVICE_REPORTS_LOCKED"
	case "InvalidHostID", "InvalidPairRecord", "MissingPairRecord":
		return "PAIRING_RECORD_REJECTED", "DEVICE_REPORTS_PAIRING_UNAVAILABLE"
	default:
		return "OTHER_DEVICE_ERROR", "UNKNOWN_NOT_AUTHENTICATED"
	}
}
