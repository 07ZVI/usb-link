package ipadncm

import (
	"strings"
	"time"
)

type amdsReplugGate struct {
	absentSince time.Time
	detached    bool
}

func (g *amdsReplugGate) observe(now time.Time, p idlePresence, root string) (ready bool, changed bool) {
	if !g.detached {
		if !p.readable || !p.absent {
			g.absentSince = time.Time{}
			return
		}
		if g.absentSince.IsZero() {
			g.absentSince = now
			return
		}
		g.detached = now.Sub(g.absentSince) >= time.Second
		return
	}
	if p.candidate {
		return strings.EqualFold(p.identity, root), !strings.EqualFold(p.identity, root)
	}
	return
}
