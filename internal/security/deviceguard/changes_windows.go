//go:build windows && amd64

package deviceguard

import (
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// SDK CM_NOTIFY_FILTER uses a 200-WCHAR union at offset 16.
type notifyFilter struct {
	Size, Flags, Kind, Reserved uint32
	Instance                    [200]uint16
}

var _ [416 - unsafe.Sizeof(notifyFilter{})]byte
var _ [unsafe.Sizeof(notifyFilter{}) - 416]byte
var registerChange = cfg.NewProc("CM_Register_Notification")
var unregisterChange = cfg.NewProc("CM_Unregister_Notification")
var copyNotificationData = windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlMoveMemory")
var changes = struct {
	sync.Mutex
	next      uintptr
	listeners map[uintptr]chan struct{}
	filters   map[uintptr]func(string) bool
}{listeners: make(map[uintptr]chan struct{}), filters: make(map[uintptr]func(string) bool)}
var changeEvents, changeFallbacks atomic.Uint64

// Bounded, serial-free log of device notifications for remote diagnosis.
var recentChanges = struct {
	sync.Mutex
	events []map[string]string
}{}

func recordChange(action uintptr, instance string) {
	name := map[uintptr]string{7: "enumerated", 8: "started", 9: "removed"}[action]
	device := instance
	if parts := strings.SplitN(instance, `\`, 3); len(parts) >= 2 {
		device = parts[0] + `\` + parts[1]
	}
	recentChanges.Lock()
	recentChanges.events = append(recentChanges.events, map[string]string{"utc": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), "action": name, "device": device})
	if len(recentChanges.events) > 60 {
		recentChanges.events = append([]map[string]string(nil), recentChanges.events[len(recentChanges.events)-60:]...)
	}
	recentChanges.Unlock()
}

var changeCallback = windows.NewCallback(func(h, id, action, data, size uintptr) uintptr {
	if action >= 7 && action <= 9 {
		if data != 0 && size >= 10 && size <= 4096 {
			metadata := make([]byte, int(size))
			copyNotificationData.Call(uintptr(unsafe.Pointer(&metadata[0])), data, size)
			if instance, ok := notificationInstance(metadata); ok {
				recordChange(action, instance)
			}
		}
		changes.Lock()
		ch := changes.listeners[id]
		match := changes.filters[id]
		changes.Unlock()
		if match != nil {
			if data == 0 || size < 10 || size > 4096 {
				return 0
			}
			// Copy while the callback owns the event-data lifetime; never retain
			// or convert the callback's uintptr into a Go heap pointer.
			metadata := make([]byte, int(size))
			copyNotificationData.Call(uintptr(unsafe.Pointer(&metadata[0])), data, size)
			instance, ok := notificationInstance(metadata)
			if !ok || !match(instance) {
				return 0
			}
		}
		if ch != nil {
			changeEvents.Add(1)
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
	return 0
})

// Register before admission recheck; callbacks only enqueue a coalesced wake.
func SubscribeChanges() (<-chan struct{}, func(), error) {
	return subscribeChanges(nil)
}

// Filter only notification metadata. It is a wake hint, never device authority.
func SubscribeFilteredChanges(match func(string) bool) (<-chan struct{}, func(), error) {
	if match == nil {
		return nil, nil, fmt.Errorf("device notification filter required")
	}
	return subscribeChanges(match)
}
func subscribeChanges(match func(string) bool) (<-chan struct{}, func(), error) {
	if match != nil {
		if e := copyNotificationData.Find(); e != nil {
			return nil, nil, e
		}
	}
	if e := registerChange.Find(); e != nil {
		changeFallbacks.Add(1)
		return nil, nil, e
	}
	if e := unregisterChange.Find(); e != nil {
		changeFallbacks.Add(1)
		return nil, nil, e
	}
	changes.Lock()
	if len(changes.listeners) >= 128 {
		changes.Unlock()
		changeFallbacks.Add(1)
		return nil, nil, fmt.Errorf("device notification limit")
	}
	changes.next++
	id := changes.next
	ch := make(chan struct{}, 1)
	changes.listeners[id] = ch
	changes.filters[id] = match
	changes.Unlock()
	f := notifyFilter{Size: 416, Flags: 2, Kind: 2}
	var h uintptr
	rc, _, _ := registerChange.Call(uintptr(unsafe.Pointer(&f)), id, changeCallback, uintptr(unsafe.Pointer(&h)))
	if rc != 0 {
		changes.Lock()
		delete(changes.listeners, id)
		delete(changes.filters, id)
		changes.Unlock()
		changeFallbacks.Add(1)
		return nil, nil, fmt.Errorf("CM_Register_Notification: %d", rc)
	}
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			rc, _, _ := unregisterChange.Call(h)
			if rc == 0 {
				changes.Lock()
				delete(changes.listeners, id)
				delete(changes.filters, id)
				changes.Unlock()
			}
		})
	}, nil
}
func recentChangeEvents() []map[string]string {
	recentChanges.Lock()
	defer recentChanges.Unlock()
	return append([]map[string]string{}, recentChanges.events...)
}
func ChangeDiagnostics() any {
	changes.Lock()
	n := len(changes.listeners)
	changes.Unlock()
	return map[string]any{"backend": "CM device-instance notifications; 2s polling if registration fails", "active_registrations": n, "callbacks": changeEvents.Load(), "polling_fallbacks": changeFallbacks.Load(), "polling_baseline": pollingBaseline.Load(), "recent": recentChangeEvents()}
}

var baselineTimer struct {
	sync.Mutex
	timer      *time.Timer
	generation uint64
}

func SetPollingBaseline(seconds int) {
	baselineTimer.Lock()
	defer baselineTimer.Unlock()
	baselineTimer.generation++
	g := baselineTimer.generation
	if baselineTimer.timer != nil {
		baselineTimer.timer.Stop()
	}
	pollingBaseline.Store(seconds > 0)
	wakeGuardChanges()
	if seconds > 0 {
		baselineTimer.timer = time.AfterFunc(time.Duration(seconds)*time.Second, func() {
			baselineTimer.Lock()
			defer baselineTimer.Unlock()
			if baselineTimer.generation == g {
				pollingBaseline.Store(false)
				wakeGuardChanges()
				baselineTimer.timer = nil
			}
		})
	}
}
func wakeGuardChanges() {
	changes.Lock()
	defer changes.Unlock()
	for id, ch := range changes.listeners {
		if changes.filters[id] != nil {
			continue
		}
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}
