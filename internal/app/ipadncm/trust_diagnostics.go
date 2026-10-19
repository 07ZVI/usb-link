package ipadncm

import (
	"fmt"
	"sort"
)

// Observed PnP node shape. It is retained only because NCM Direct normalizes
// its own bounded node list with it; the standalone trust timeline sampler that
// once shared these types has been removed.
const trustNodeLimit = 4

type trustNodeState struct {
	Role     string `json:"role"`
	Service  string `json:"service"`
	Problem  uint32 `json:"problem"`
	Readable bool   `json:"cm_readable"`
	Started  bool   `json:"started"`
	Restart  bool   `json:"restart_required"`
}
type trustPNPState struct {
	Read     string           `json:"read"`
	Roots    int              `json:"roots"`
	Controls int              `json:"controls"`
	Nodes    []trustNodeState `json:"nodes"`
	Omitted  int              `json:"nodes_omitted"`
}

func trustObservationCode(s string) string {
	switch s {
	case "ok", "access_denied", "not_installed", "timeout", "cancelled", "query_failed", "enumeration_limit", "invalid_state", "unavailable":
		return s
	}
	return "query_failed"
}

func normalizeTrustPNP(p trustPNPState) trustPNPState {
	p.Read = trustObservationCode(p.Read)
	if p.Read != "ok" {
		return trustPNPState{Read: p.Read}
	}
	nodes := append([]trustNodeState(nil), p.Nodes...)
	for i := range nodes {
		switch nodes[i].Role {
		case "R", "00", "01", "02", "04", "03", "05":
		default:
			nodes[i].Role = "other"
		}
		switch nodes[i].Service {
		case "C", "N", "A", "W", "P", "F", "S", "X":
		default:
			nodes[i].Service = "U"
		}
	}
	sort.Slice(nodes, func(i, j int) bool {
		if a, b := trustNodePriority(nodes[i]), trustNodePriority(nodes[j]); a != b {
			return a < b
		}
		return trustNodeCode(nodes[i]) < trustNodeCode(nodes[j])
	})
	p.Omitted = max(0, p.Omitted)
	if len(nodes) > trustNodeLimit {
		p.Omitted += len(nodes) - trustNodeLimit
		// Reserve one slot for each relevant role before duplicate nodes. The
		// observer covers all roots; a second device must not hide MI01 or NCM.
		selected := make([]trustNodeState, 0, trustNodeLimit)
		used := make([]bool, len(nodes))
		for _, category := range []int{0, 1, 2, 3} {
			for i, n := range nodes {
				rank := trustNodePriority(n)
				if rank == category || category == 3 && rank == 4 {
					selected, used[i] = append(selected, n), true
					break
				}
			}
		}
		for i, n := range nodes {
			if len(selected) == trustNodeLimit {
				break
			}
			if !used[i] {
				selected = append(selected, n)
			}
		}
		nodes = selected
	}
	p.Nodes = nodes
	p.Roots, p.Controls = max(0, min(p.Roots, 4096)), max(0, min(p.Controls, 4096))
	return p
}

func trustNodePriority(n trustNodeState) int {
	switch n.Role {
	case "R":
		return 0
	case "00":
		return 1
	case "01":
		return 2
	}
	if n.Service == "N" {
		if n.Readable && n.Started && n.Problem == 0 && !n.Restart {
			return 3
		}
		return 4
	}
	return 5
}

func trustNodeCode(n trustNodeState) string {
	return fmt.Sprintf("%s/%s/%d/%d/%d/%d", n.Role, n.Service, n.Problem, trustBool(n.Readable), trustBool(n.Started), trustBool(n.Restart))
}
func trustBool(v bool) int {
	if v {
		return 1
	}
	return 0
}
