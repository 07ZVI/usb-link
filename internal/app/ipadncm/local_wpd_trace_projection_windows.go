//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"encoding/binary"
	"golang.org/x/sys/windows"
	"unsafe"
)

// ABI-equivalent borrowed view; no pointer or raw data enters either queue.
type wpdProjectionRecordView struct {
	Header                            wpdEventHeader
	BufferContext                     uint32
	ExtendedDataCount, UserDataLength uint16
	ExtendedData                      uintptr
	Data                              *byte
	UserContext                       uintptr
}

func (b *localWPDTraceNative) projectRecord(r *wpdEventRecord, provider windows.GUID, ms int64, attempt uint64) wpdCriticalItem {
	item := wpdCriticalItem{projected: true, attempt: attempt, ms: ms, shape: wpdNativeRecordShape(r)}
	label := "unknown"
	if provider != (windows.GUID{}) && r.Header.Provider == provider {
		label = "mtp"
	}
	item.event = wpdEventSummary(r.Header, label, ms)
	item.schema = localWPDTraceSchema{Provider: label, EventID: r.Header.Descriptor.ID, Version: r.Header.Descriptor.Version, HeaderFlags: r.Header.Flags, DataLength: r.UserDataLength}
	capture := wpdCriticalCapture{providerMatched: label == "mtp", id: r.Header.Descriptor.ID, version: r.Header.Descriptor.Version, headerSize: r.Header.Size, flags: r.Header.Flags, dataLength: r.UserDataLength, dataPointer: r.UserData != 0, extendedCount: r.ExtendedDataCount, extendedPointer: r.ExtendedData != 0}
	item.stage = capture.rejection()
	if item.stage == "" && r.Header.Flags & ^uint16(0x20|0x40|0x80|0x200) != 0 {
		item.stage = "header_flags_unsupported"
	}
	if item.stage == "" {
		var descriptor [16]byte
		copy(descriptor[:], unsafe.Slice((*byte)(unsafe.Pointer(&r.Header.Descriptor)), 16))
		matched := false
		for _, d := range b.projections {
			if d.Descriptor == descriptor {
				matched = true
				break
			}
		}
		if !matched {
			item.stage = "strict_manifest_template_mismatch"
		}
	}
	if item.stage == "" {
		// Bounds are established before each scalar read. Neither parameter arrays
		// nor binary body bytes are accessed, even when they contain private data.
		data := (*wpdProjectionRecordView)(unsafe.Pointer(r)).Data
		code, response, stage := wpdProjectMTP(r.Header.Descriptor.ID, r.UserDataLength, func(offset, size int) uint64 {
			bytes := unsafe.Slice((*byte)(unsafe.Add(unsafe.Pointer(data), offset)), size)
			if size == 2 {
				return uint64(binary.LittleEndian.Uint16(bytes))
			}
			return uint64(binary.LittleEndian.Uint32(bytes))
		})
		item.stage = stage
		if stage == "decoded" {
			item.event.CommandField = "MTP_Opcode"
			item.event.CommandCode = uint64(code)
			item.event.OpcodeDecoded = true
			item.event.Response = response
			item.event.CommandRole = wpdDecodedCommandRole(item.event)
		}
	}
	var header [wpdCriticalHeaderSize]byte
	copy(header[:], unsafe.Slice((*byte)(unsafe.Pointer(&r.Header)), wpdCriticalHeaderSize))
	item.correlation = wpdCriticalHeaderCorrelation(header)
	item.schema.Stage = item.stage
	return item
}

func (b *localWPDTraceNative) captureCriticalProjection(r *wpdEventRecord, item wpdCriticalItem) {
	if item.event.Provider != "mtp" || (item.event.EventID != 2000 && item.event.EventID != 2001) {
		return
	}
	b.mu.Lock()
	q := b.critical
	b.mu.Unlock()
	b.enqueueProjection(q, item)
}
func (b *localWPDTraceNative) captureSummaryProjection(r *wpdEventRecord, item wpdCriticalItem) {
	b.mu.Lock()
	q := b.summaryQueue
	b.mu.Unlock()
	b.enqueueProjection(q, item)
}
func (b *localWPDTraceNative) enqueueProjection(q *wpdCriticalQueue, item wpdCriticalItem) {
	if q == nil {
		return
	}
	// The queue contains only the projection, including fixed rejection reasons.
	reason := q.enqueue(wpdCriticalCapture{summary: true, headerSize: 80}, func(dst *wpdCriticalItem) { *dst = item })
	if reason != "" {
		RecordConnectionArchiveEvent("wpd_critical_rejected", struct {
			Attempt uint64             `json:"software_attempt"`
			Reason  string             `json:"reason"`
			Header  localWPDTraceEvent `json:"header"`
		}{item.attempt, reason, item.event})
	}
}
