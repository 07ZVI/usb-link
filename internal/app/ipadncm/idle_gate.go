package ipadncm

import (
	"strings"
	"time"
)

type idlePresence struct {
	candidate, absent, readable bool
	identity                    string
}

// Only cached PnP identifiers are examined. Child interfaces do not count as
// attached roots; failed enumeration never proves physical absence.
func idlePresenceFromIDs(ids []string, complete bool) idlePresence {
	if !complete {
		return idlePresence{}
	}
	mobile, target := 0, 0
	for _, id := range ids {
		parts := strings.SplitN(strings.ToUpper(id), `\`, 3)
		if len(parts) != 3 || parts[0] != "USB" || parts[2] == "" {
			continue
		}
		if strings.HasPrefix(parts[1], "VID_05AC&PID_12") && !strings.Contains(parts[1], "&MI_") {
			mobile++
			if parts[1] == "VID_05AC&PID_12AB" {
				target++
			}
		}
	}
	return idlePresence{candidate: mobile == 1 && target == 1, absent: mobile == 0, readable: true}
}

type idleReconnectGate struct {
	absentSince time.Time
	minimum     time.Duration
}

func (g *idleReconnectGate) detached(now time.Time, p idlePresence) bool {
	if !p.readable || !p.absent {
		g.absentSince = time.Time{}
		return false
	}
	if g.absentSince.IsZero() {
		g.absentSince = now
		return false
	}
	minimum := g.minimum
	if minimum == 0 {
		minimum = 15 * time.Second
	}
	return now.Sub(g.absentSince) >= minimum
}

// Route one supported USB root without contacting Apple services or hardware.
func idleUSBPresenceFromIDs(ids []string, complete bool) (string, idlePresence) {
	if !complete {
		return "", idlePresence{}
	}
	roots := 0
	kind := ""
	identity := ""
	for _, id := range ids {
		p := strings.SplitN(strings.ToUpper(id), `\`, 3)
		if len(p) != 3 || p[0] != "USB" || p[2] == "" || strings.Contains(p[1], "&MI_") {
			continue
		}
		if strings.HasPrefix(p[1], "VID_05AC&PID_12") || p[1] == "VID_05AC&PID_1903" {
			roots++
			identity = strings.ToUpper(id)
			if p[1] == "VID_05AC&PID_12AB" {
				kind = "iPad"
			}
			if p[1] == "VID_05AC&PID_1903" {
				kind = "Mac"
			}
		}
	}
	if roots != 1 {
		kind = ""
	}
	return kind, idlePresence{candidate: roots == 1 && kind != "", absent: roots == 0, readable: true, identity: identity}
}

// A stable, different supported root can rearm even when the user swaps devices
// faster than the absence debounce. Multiple/unreadable roots never authorize it.
type idleNewDeviceGate struct {
	identity string
	since    time.Time
}

func (g *idleNewDeviceGate) ready(now time.Time, previous string, p idlePresence) bool {
	if !p.readable || !p.candidate || p.identity == "" || previous == "" || p.identity == previous {
		g.identity = ""
		g.since = time.Time{}
		return false
	}
	if g.identity != p.identity {
		g.identity = p.identity
		g.since = now
		return false
	}
	return now.Sub(g.since) >= time.Second
}

// Once an established session has ended with verified cleanup, a stable USB
// root can start a fresh session even if unplug/replug occurred during cleanup.
// Failed attempts need an observed absence before the same root can rearm.
type idleReattachGate struct {
	absent           bool
	stable           sameAttachmentGate
	confirmedAbsence idleReconnectGate
	fastReplug       bool
}

func (g *idleReattachGate) ready(now time.Time, previous string, p idlePresence, completed bool) bool {
	if p.readable && p.absent {
		g.absent = true
	}
	// A previously running session and sustained absence separate the attempts.
	// Do not spend another two seconds delaying that same, freshly read root.
	if !p.readable || !p.absent && (!p.candidate || previous == "" || p.identity != previous) {
		g.fastReplug = false
	}
	g.confirmedAbsence.minimum = 2 * time.Second
	if g.confirmedAbsence.detached(now, p) {
		g.fastReplug = true
	}
	if completed && g.fastReplug && p.readable && !p.absent && p.candidate && previous != "" && p.identity == previous {
		return true
	}
	if !completed && !g.absent {
		return false
	}
	return g.stable.ready(now, previous, p)
}

// The iPad loop excludes Mac roots; a Mac can remain active independently.
func onlyIPadIDs(ids []string) []string {
	var out []string
	for _, id := range ids {
		if strings.Contains(strings.ToUpper(id), "VID_05AC&PID_12") {
			out = append(out, id)
		}
	}
	return out
}

func onlyMacIDs(ids []string) []string {
	var out []string
	for _, id := range ids {
		if strings.Contains(strings.ToUpper(id), "VID_05AC&PID_1903") {
			out = append(out, id)
		}
	}
	return out
}
