//go:build windows && amd64 && usblink_local_remote

package ipadncm

import (
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func wpdEventSummary(header wpdEventHeader, label string, receivedMS int64) localWPDTraceEvent {
	event := localWPDTraceEvent{Provider: label, EventID: header.Descriptor.ID, Version: header.Descriptor.Version, PID: header.ProcessID, Task: header.Descriptor.Task, ETWOpcode: header.Descriptor.Opcode, MS: receivedMS}
	if header.Timestamp >= 116444736000000000 && header.Timestamp < 200000000000000000 {
		event.EventUTC = time.Unix(0, (header.Timestamp-116444736000000000)*100).UTC().Format(time.RFC3339Nano)
	}
	return event
}

func decodeWPDCritical(item *wpdCriticalItem) (event localWPDTraceEvent, stage string, native uint32) {
	if item.projected {
		return item.event, item.stage, 0
	}
	var record wpdEventRecord
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&record.Header)), wpdCriticalHeaderSize), item.header[:])
	event = wpdEventSummary(record.Header, "mtp", item.ms)
	var provider windows.GUID
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&provider)), 16), item.provider[:])
	if provider == (windows.GUID{}) || record.Header.Provider != provider || !wpdValidEventRecordSize(record.Header.Size) || record.Header.Flags&1 != 0 || record.Header.Descriptor.Version != 0 || (record.Header.Descriptor.ID != 2000 && record.Header.Descriptor.ID != 2001) || item.length == 0 || int(item.length) > len(item.payload) {
		return event, "private_record_invalid", 0
	}
	// TDH receives only this worker-owned, pinned copy. Extended pointers and
	// callback context are zero; no callback/native memory survives admission.
	var pinned runtime.Pinner
	pinned.Pin(&item.payload[0])
	defer pinned.Unpin()
	record.BufferContext = item.bufferContext
	record.UserDataLength = item.length
	record.UserData = uintptr(unsafe.Pointer(&item.payload[0]))
	defer func() { runtime.KeepAlive(item) }()
	metadata, stage, native := wpdEventMetadata(&record)
	if stage != "" {
		return event, stage, native
	}
	if stage := wpdCriticalTemplateStage(item.provider, event.EventID, event.Version, metadata); stage != "" {
		return event, stage, 0
	}
	field, value, schema, response := wpdDecodeCommand(&record, metadata, "", 0, true)
	event.CommandField, event.CommandCode, event.OpcodeDecoded = field, value, schema.Stage == "decoded"
	event.Response = response
	if event.OpcodeDecoded {
		event.CommandRole = wpdDecodedCommandRole(event)
	}
	return event, schema.Stage, schema.NativeCode
}

func (b *localWPDTraceNative) startCriticalConsumer() {
	queue := newWPDCriticalQueue()
	done := make(chan struct{})
	b.mu.Lock()
	b.critical, b.criticalDone = queue, done
	b.mu.Unlock()
	go func() {
		defer close(done)
		var lastPID uint32
		for {
			item, found, closed := queue.pop()
			if !found {
				if closed {
					return
				}
				<-queue.wake
				continue
			}
			event, stage, native := decodeWPDCritical(&item)
			if event.PID != 0 && event.PID != lastPID {
				RecordConnectionEnvironmentPID(event.PID)
				lastPID = event.PID
			}
			archived := RecordConnectionArchiveEventAccepted("wpd_critical_event", struct {
				Attempt     uint64                 `json:"software_attempt"`
				Event       localWPDTraceEvent     `json:"event"`
				Stage       string                 `json:"stage"`
				Native      uint32                 `json:"native_code"`
				Correlation wpdCriticalCorrelation `json:"correlation"`
				Shape       wpdRecordShape         `json:"record_shape"`
			}{item.attempt, event, stage, native, item.safeCorrelation(), item.recordShape()})
			responseFailed := event.OpcodeDecoded && event.EventID == 2001 && (!event.Response.CodeRead || !event.Response.TransportRead)
			item = wpdCriticalItem{}
			runtime.KeepAlive(&item)
			queue.complete(event.OpcodeDecoded, responseFailed, archived)
		}
	}()
}

// Call only after ProcessTrace/callbacks have joined. Buffered events were
// captured while enabled; drain those copies, then retain counts but no bytes.
func (b *localWPDTraceNative) closeCriticalConsumer() {
	b.mu.Lock()
	queue, done := b.critical, b.criticalDone
	b.mu.Unlock()
	if queue == nil {
		return
	}
	queue.close()
	<-done
	counts := queue.snapshot()
	b.mu.Lock()
	b.data.CriticalArchive = counts
	b.critical, b.criticalDone = nil, nil
	b.mu.Unlock()
	RecordConnectionArchiveEvent("wpd_critical_stats", counts)
}

func (b *localWPDTraceNative) decodeSummaryCopy(item *wpdCriticalItem) (bool, bool, bool) {
	if item.projected {
		return b.publishSummaryProjection(item)
	}
	var record wpdEventRecord
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&record.Header)), wpdCriticalHeaderSize), item.header[:])
	var providers [3]windows.GUID
	for i := range providers {
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&providers[i])), 16), item.catalog[i][:])
	}
	var pinned runtime.Pinner
	pinned.Pin(&item.payload[0])
	defer pinned.Unpin()
	record.BufferContext, record.UserDataLength = item.bufferContext, item.length
	record.UserData = uintptr(unsafe.Pointer(&item.payload[0]))
	defer func() { runtime.KeepAlive(item) }()
	return b.decodeSummary(&record, providers, item.ms, item.attempt)
}

func (b *localWPDTraceNative) startSummaryConsumer() {
	queue, done := newWPDCriticalQueue(), make(chan struct{})
	b.mu.Lock()
	b.summaryQueue, b.summaryDone = queue, done
	b.mu.Unlock()
	go func() {
		defer close(done)
		for {
			item, found, closed := queue.pop()
			if !found {
				if closed {
					return
				}
				<-queue.wake
				continue
			}
			decoded, responseFailed, archived := b.decodeSummaryCopy(&item)
			item = wpdCriticalItem{}
			runtime.KeepAlive(&item)
			queue.complete(decoded, responseFailed, archived)
		}
	}()
}

func (b *localWPDTraceNative) closeSummaryConsumer() {
	b.mu.Lock()
	queue, done := b.summaryQueue, b.summaryDone
	b.mu.Unlock()
	if queue == nil {
		return
	}
	queue.close()
	<-done
	counts := queue.snapshot()
	b.mu.Lock()
	b.data.SummaryArchive = counts
	b.summaryQueue, b.summaryDone = nil, nil
	b.mu.Unlock()
}

func wpdNativeRecordShape(r *wpdEventRecord) wpdRecordShape {
	return wpdRecordShape{RecordBytes: r.Header.Size, HeaderBytes: wpdCriticalHeaderSize, UserDataBytes: r.UserDataLength, HeaderFlags: r.Header.Flags, ExtendedCount: r.ExtendedDataCount}
}

func (b *localWPDTraceNative) publishSummaryProjection(item *wpdCriticalItem) (bool, bool, bool) {
	event, schema := item.event, item.schema
	b.mu.Lock()
	if event.OpcodeDecoded {
		b.data.Decoded++
		b.data.retainDecoded(event)
	}
	b.data.recordDecode(schema)
	b.data.Recent = append(b.data.Recent, event)
	if len(b.data.Recent) > 8 {
		b.data.Recent = append([]localWPDTraceEvent(nil), b.data.Recent[len(b.data.Recent)-8:]...)
	}
	b.mu.Unlock()
	archived := RecordConnectionArchiveEventAccepted("wpd_event", struct {
		Attempt uint64              `json:"software_attempt"`
		Event   localWPDTraceEvent  `json:"event"`
		Schema  localWPDTraceSchema `json:"schema"`
	}{item.attempt, event, schema})
	return event.OpcodeDecoded, false, archived
}
