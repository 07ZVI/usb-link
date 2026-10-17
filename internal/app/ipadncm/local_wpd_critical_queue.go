package ipadncm

import "sync"

const wpdCriticalCapacity = 128
const wpdCriticalPayloadLimit = 4096
const wpdCriticalHeaderSize = 80

type wpdCriticalArchiveCounts struct {
	Seen             uint64 `json:"seen"`
	Enqueued         uint64 `json:"enqueued"`
	Rejected         uint64 `json:"rejected"`
	RejectedExtended uint64 `json:"rejected_extended"`
	RejectedLength   uint64 `json:"rejected_length"`
	Overflow         uint64 `json:"overflow"`
	Decoded          uint64 `json:"decoded"`
	Failed           uint64 `json:"failed"`
	ResponseFailures uint64 `json:"response_read_failed"`
	ArchiveEnqueued  uint64 `json:"archive_enqueued"`
	ArchiveNotQueued uint64 `json:"archive_not_enqueued"`
	Pending          uint32 `json:"pending"`
	InFlight         uint32 `json:"in_flight"`
	HighWater        uint32 `json:"high_water"`
	Closed           bool   `json:"closed"`
}

// Private memory only. Neither raw header nor payload is a diagnostic value.
type wpdCriticalItem struct {
	projected     bool
	event         localWPDTraceEvent
	stage         string
	schema        localWPDTraceSchema
	correlation   wpdCriticalCorrelation
	shape         wpdRecordShape
	header        [wpdCriticalHeaderSize]byte
	payload       [wpdCriticalPayloadLimit]byte
	provider      [16]byte
	catalog       [3][16]byte
	bufferContext uint32
	length        uint16
	ms            int64
	attempt       uint64
}

type wpdCriticalCapture struct {
	summary                           bool
	providerMatched                   bool
	id, headerSize, flags, dataLength uint16
	version                           uint8
	extendedCount                     uint16
	extendedPointer, dataPointer      bool
}

// EVENT_HEADER.Size describes the event record, not sizeof(EVENT_HEADER).
// It never controls our copy length: header and UserData bounds are separate.
// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
func wpdValidEventRecordSize(size uint16) bool { return size >= wpdCriticalHeaderSize }

func (c wpdCriticalCapture) rejection() string {
	switch {
	case !c.summary && !c.providerMatched:
		return "provider_unproven"
	case !c.summary && c.id != 2000 && c.id != 2001:
		return "event_not_selected"
	case !c.summary && c.version != 0:
		return "version_not_selected"
	case !wpdValidEventRecordSize(c.headerSize):
		return "header_size_invalid"
	// Extended data can contain additional pointers. Copying it is deliberately
	// unsupported; TDH receives a self-contained manifest record only.
	case c.extendedCount != 0 || c.extendedPointer || c.flags&1 != 0:
		return "extended_data_unsupported"
	case c.dataLength > wpdCriticalPayloadLimit || (c.dataLength != 0 && !c.dataPointer) || (!c.summary && c.dataLength == 0):
		return "payload_size_invalid"
	default:
		return ""
	}
}

type wpdCriticalQueue struct {
	mu    sync.Mutex
	items [wpdCriticalCapacity]wpdCriticalItem
	head  int
	count int
	stats wpdCriticalArchiveCounts
	wake  chan struct{}
}

func newWPDCriticalQueue() *wpdCriticalQueue {
	return &wpdCriticalQueue{wake: make(chan struct{}, 1)}
}

// fill copies callback-owned memory while it is valid. It may only copy bytes;
// no TDH, device reads, logging or worker callbacks run under this lock.
func (q *wpdCriticalQueue) enqueue(c wpdCriticalCapture, fill func(*wpdCriticalItem)) string {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.stats.Seen++
	if reason := c.rejection(); reason != "" {
		q.stats.Rejected++
		if reason == "extended_data_unsupported" {
			q.stats.RejectedExtended++
		}
		if reason == "payload_size_invalid" {
			q.stats.RejectedLength++
		}
		return reason
	}
	if q.stats.Closed {
		q.stats.Rejected++
		return "consumer_closed"
	}
	if q.count == len(q.items) {
		q.stats.Overflow++
		return "queue_full"
	}
	slot := (q.head + q.count) % len(q.items)
	fill(&q.items[slot])
	q.items[slot].length = c.dataLength
	q.count++
	q.stats.Enqueued++
	q.stats.Pending = uint32(q.count)
	q.stats.HighWater = max(q.stats.HighWater, uint32(q.count))
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return ""
}

func (q *wpdCriticalQueue) pop() (wpdCriticalItem, bool, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.count == 0 {
		return wpdCriticalItem{}, false, q.stats.Closed
	}
	item := q.items[q.head]
	q.items[q.head] = wpdCriticalItem{}
	q.head = (q.head + 1) % len(q.items)
	q.count--
	q.stats.Pending = uint32(q.count)
	q.stats.InFlight++
	return item, true, false
}

func (q *wpdCriticalQueue) complete(decoded, responseFailed, archived bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if decoded {
		q.stats.Decoded++
	} else {
		q.stats.Failed++
	}
	if responseFailed {
		q.stats.ResponseFailures++
	}
	if archived {
		q.stats.ArchiveEnqueued++
	} else {
		q.stats.ArchiveNotQueued++
	}
	q.stats.InFlight--
}

func (q *wpdCriticalQueue) close() {
	q.mu.Lock()
	q.stats.Closed = true
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *wpdCriticalQueue) snapshot() wpdCriticalArchiveCounts {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.stats
}
