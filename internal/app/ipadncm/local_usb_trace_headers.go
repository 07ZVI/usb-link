package ipadncm

// Only fixed header scalars are retained for rejected records. In particular,
// session metadata and foreign providers never cause a payload read.
type usbTraceCallbackHeader struct {
	Size, Flags, ExtendedCount, DataLength uint16
	ID                                     uint16
	Version, Opcode                        uint8
	HasData                                bool
}

type usbTraceRejectedHeader struct {
	Provider string `json:"provider"`
	Reason   string `json:"reason"`
	EventID  uint16 `json:"event_id"`
	Version  uint8  `json:"version"`
	Opcode   uint8  `json:"opcode"`
	Size     uint16 `json:"header_size"`
	Flags    uint16 `json:"header_flags"`
	Extended uint16 `json:"extended_count"`
	Length   uint16 `json:"data_length"`
	Count    uint64 `json:"count"`
}

func usbTraceHeaderProvider(label string) string {
	switch label {
	case "USBHUB3", "UCX", "USBXHCI", "session_metadata":
		return label
	}
	return "other_provider"
}

func (s *usbTraceStatus) rejectHeader(provider, reason string, h usbTraceCallbackHeader) {
	provider = usbTraceHeaderProvider(provider)
	switch reason {
	case "header_too_short", "provider_unrecognized", "header_flags", "extended_data", "data_bound_or_null", "template_not_enabled", "scalar_invalid":
	default:
		reason = "unknown_rejection"
	}
	r := usbTraceRejectedHeader{Provider: provider, Reason: reason, EventID: h.ID, Version: h.Version, Opcode: h.Opcode, Size: h.Size, Flags: h.Flags, Extended: h.ExtendedCount, Length: h.DataLength}
	for i := 0; i < s.RejectedHeaderCount; i++ {
		old := s.RejectedHeaders[i]
		old.Count = 0
		if old == r {
			s.RejectedHeaders[i].Count++
			return
		}
	}
	if s.RejectedHeaderCount == len(s.RejectedHeaders) {
		s.RejectedHeaderOmitted++
		return
	}
	r.Count = 1
	s.RejectedHeaders[s.RejectedHeaderCount] = r
	s.RejectedHeaderCount++
}

func (s *usbTraceStatus) admitHeader(provider string, h usbTraceCallbackHeader) bool {
	s.CallbacksReceived++
	provider = usbTraceHeaderProvider(provider)
	if h.Size < 80 {
		s.HeaderRejected++
		s.rejectHeader(provider, "header_too_short", h)
		return false
	}
	if provider == "session_metadata" {
		s.SessionMetadata++
		if h.Opcode == 0 {
			s.SessionHeaders++
		}
		return false
	}
	if provider == "other_provider" {
		s.UnknownProvider++
		s.rejectHeader(provider, "provider_unrecognized", h)
		return false
	}
	s.Received++
	reason := ""
	switch {
	case h.Flags&(0x4|0x8) != 0:
		reason = "header_flags"
	case h.ExtendedCount != 0:
		reason = "extended_data"
	case h.DataLength > 32 || h.DataLength > 0 && !h.HasData:
		reason = "data_bound_or_null"
	}
	if reason != "" {
		s.ShapeRejected++
		s.SchemaRejected++
		s.rejectHeader(provider, reason, h)
		return false
	}
	return true
}
