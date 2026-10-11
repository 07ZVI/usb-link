package deviceguard

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
	"time"
)

// USBList groups display rows by observed physical topology. It never changes
// admission identities or treats a display group as an approved device.
func USBList(nodes []securitypolicy.DeviceNode, complete bool) ([]securitypolicy.DeviceRecord, error) {
	if !complete || len(nodes) > 4096 {
		return nil, fmt.Errorf("USB_DEVICE_LIST_UNAVAILABLE")
	}
	index := map[string]securitypolicy.DeviceNode{}
	for _, n := range nodes {
		id := strings.ToUpper(n.ID)
		if _, ok := index[id]; ok {
			return nil, fmt.Errorf("USB_DEVICE_LIST_AMBIGUOUS")
		}
		index[id] = n
	}
	roots := []string{}
	for id := range index {
		if physicalUSBRoot(id) {
			roots = append(roots, id)
		}
	}
	sort.Strings(roots)
	parents := map[string]string{}
	for _, id := range roots {
		parents[id] = id
	}
	var find func(string) string
	find = func(id string) string {
		if parents[id] != id {
			parents[id] = find(parents[id])
		}
		return parents[id]
	}
	join := func(a, b string) {
		a, b = find(a), find(b)
		if a > b {
			a, b = b, a
		}
		parents[b] = a
	}
	// A child of a non-hub physical USB node is a function of that node. Devices
	// on two downstream ports of a hub remain separate, even with identical names.
	for _, id := range roots {
		seen := map[string]bool{id: true}
		p := strings.ToUpper(index[id].Parent)
		for hops := 0; p != "" && hops < 64 && !seen[p]; hops++ {
			seen[p] = true
			n, ok := index[p]
			if !ok {
				break
			}
			if physicalUSBRoot(p) {
				if !isHub(n) {
					join(id, p)
				}
				break
			}
			p = strings.ToUpper(n.Parent)
		}
	}
	containers := map[string][]string{}
	ports := map[string]string{}
	for _, id := range roots {
		n := index[id]
		c := strings.ToUpper(n.ContainerID)
		if c != "" {
			containers[c] = append(containers[c], id)
		}
		for _, path := range n.LocationPaths {
			if key := usbPortPath(path); key != "" {
				if other, ok := ports[key]; ok {
					join(id, other)
				} else {
					ports[key] = id
				}
			}
		}
	}
	for _, ids := range containers {
		// Firmware can reuse container IDs. Known distinct USB port paths take
		// precedence over that conflicting metadata; missing topology stays unknown.
		conflict := false
		for i, a := range ids {
			for _, b := range ids[i+1:] {
				if distinctPorts(index[a], index[b]) && find(a) != find(b) {
					conflict = true
				}
			}
		}
		if !conflict {
			for _, id := range ids[1:] {
				join(ids[0], id)
			}
		}
	}
	groups := map[string][]string{}
	containerGroups := map[string]map[string]bool{}
	for _, id := range roots {
		g := find(id)
		groups[g] = append(groups[g], id)
		c := strings.ToUpper(index[id].ContainerID)
		if c != "" {
			if containerGroups[c] == nil {
				containerGroups[c] = map[string]bool{}
			}
			containerGroups[c][g] = true
		}
	}
	subtrees := map[string][]securitypolicy.DeviceNode{}
	for id, n := range index {
		owner := ""
		p := id
		seen := map[string]bool{}
		for hops := 0; p != "" && hops < 64 && !seen[p]; hops++ {
			seen[p] = true
			if physicalUSBRoot(p) {
				owner = find(p)
				break
			}
			pn, ok := index[p]
			if !ok {
				break
			}
			p = strings.ToUpper(pn.Parent)
		}
		if owner == "" {
			for g := range containerGroups[strings.ToUpper(n.ContainerID)] {
				if len(containerGroups[strings.ToUpper(n.ContainerID)]) == 1 {
					owner = g
				}
			}
		}
		if owner != "" {
			subtrees[owner] = append(subtrees[owner], n)
		}
	}
	out := []securitypolicy.DeviceRecord{}
	for _, id := range roots {
		if find(id) != id {
			continue
		}
		n := index[id]
		tree := subtrees[id]
		kinds := securitypolicy.ClassifyFunctions(tree)
		if onlyHub(kinds) && !occupiedHub(id, roots, index) {
			continue
		} // Port controllers and unoccupied hubs are infrastructure.
		name := cleanName(n.Name)
		// A named function can carry the product name when its parent is generic.
		sort.Slice(tree, func(i, j int) bool { return strings.ToUpper(tree[i].ID) < strings.ToUpper(tree[j].ID) })
		if genericName(name) {
			for _, child := range tree {
				candidate := cleanName(child.Name)
				if !genericName(candidate) {
					name = candidate
					break
				}
			}
		}
		h := sha256.Sum256([]byte(id))
		record := securitypolicy.DeviceRecord{Handle: hex.EncodeToString(h[:16]), Name: name, Kinds: kinds, Connected: true, Permission: securitypolicy.PermissionPending, Enforcement: securitypolicy.Evidence{State: securitypolicy.Unknown, Code: "USB_PREUSE_GATE_NOT_ENABLED", Scope: "host-usb"}, NodeCount: len(tree), MergedRoots: len(groups[id]), LastSeen: time.Now().UTC().Format(time.RFC3339)}
		for _, member := range tree {
			record.NodeIDs = append(record.NodeIDs, strings.ToUpper(member.ID))
		}
		parts := strings.Split(id, `\`)
		for _, part := range strings.Split(parts[1], "&") {
			if len(part) == 8 && strings.HasPrefix(part, "VID_") {
				record.VID = part[4:]
			}
			if len(part) == 8 && strings.HasPrefix(part, "PID_") {
				record.PID = part[4:]
			}
		}
		for _, root := range groups[id] {
			for _, path := range index[root].LocationPaths {
				if key := usbPortPath(path); key != "" {
					record.Location = key
					break
				}
			}
			if record.Location != "" {
				break
			}
		}
		describeDevice(&record, tree)
		out = append(out, record)
		if len(out) > 256 {
			return nil, fmt.Errorf("USB_DEVICE_LIST_LIMIT")
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := displayGroup(out[i].Kinds), displayGroup(out[j].Kinds)
		if a != b {
			return a < b
		}
		aName, bName := strings.ToUpper(out[i].Name), strings.ToUpper(out[j].Name)
		if aName != bName {
			return aName < bName
		}
		return out[i].Handle < out[j].Handle
	})
	return out, nil
}
func physicalUSBRoot(id string) bool {
	p := strings.Split(strings.ToUpper(id), `\`)
	return len(p) == 3 && p[0] == "USB" && strings.HasPrefix(p[1], "VID_") && !strings.Contains(p[1], "&MI_")
}
func isHub(n securitypolicy.DeviceNode) bool {
	return onlyHub(securitypolicy.ClassifyFunctions([]securitypolicy.DeviceNode{n}))
}
func onlyHub(kinds []securitypolicy.AccessoryKind) bool {
	hub := false
	for _, k := range kinds {
		if k == securitypolicy.KindHub {
			hub = true
		} else if k != securitypolicy.KindComposite && k != securitypolicy.KindUnknown {
			return false
		}
	}
	return hub
}
func displayGroup(kinds []securitypolicy.AccessoryKind) int {
	for rank, group := range [][]securitypolicy.AccessoryKind{{securitypolicy.KindKeyboard, securitypolicy.KindMouse, securitypolicy.KindHID}, {securitypolicy.KindStorage}, {securitypolicy.KindAudio, securitypolicy.KindCamera, securitypolicy.KindImaging, securitypolicy.KindMedia}, {securitypolicy.KindNetwork}, {securitypolicy.KindHub}} {
		for _, k := range kinds {
			for _, candidate := range group {
				if k == candidate {
					return rank
				}
			}
		}
	}
	return 5
}
func cleanName(name string) string {
	name = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 32 {
			return -1
		}
		return r
	}, name))
	if len(name) > 256 || name == "" {
		return "USB 裝置"
	}
	return name
}
func genericName(name string) bool {
	switch strings.ToLower(name) {
	case "usb 裝置", "usb composite device", "usb 複合裝置", "usb 复合设备", "usb input device", "usb 輸入裝置", "usb 输入设备", "hid-compliant vendor-defined device", "hid-compliant device", "hid keyboard device", "hid-compliant mouse", "scsi disk device", "usb mass storage device", "usb attached scsi (uas) mass storage device", "usb attached scsi (uas) storage device":
		return true
	}
	return false
}

// Never truncate a hub's port number or merge every port on one controller.
// LocationPaths is Windows' nonlocalized SPDRP_LOCATION_PATHS property.
func usbPortPath(path string) string {
	path = strings.ToUpper(strings.TrimSpace(path))
	if len(path) > 1024 || !strings.Contains(path, "#USB(") {
		return ""
	}
	if i := strings.Index(path, "#USBMI("); i >= 0 {
		path = path[:i]
	}
	parts := strings.Split(path, "#")
	last := parts[len(parts)-1]
	if !strings.HasPrefix(last, "USB(") || !strings.HasSuffix(last, ")") {
		return ""
	}
	for _, r := range path {
		if r < 32 {
			return ""
		}
	}
	return path
}
func distinctPorts(a, b securitypolicy.DeviceNode) bool {
	ap, bp := map[string]bool{}, map[string]bool{}
	for _, p := range a.LocationPaths {
		if k := usbPortPath(p); k != "" {
			ap[k] = true
		}
	}
	for _, p := range b.LocationPaths {
		if k := usbPortPath(p); k != "" {
			bp[k] = true
		}
	}
	if len(ap) == 0 || len(bp) == 0 {
		return false
	}
	for p := range ap {
		if bp[p] {
			return false
		}
	}
	return true
}

func occupiedHub(id string, roots []string, index map[string]securitypolicy.DeviceNode) bool {
	for _, root := range roots {
		if root == id {
			continue
		}
		p := strings.ToUpper(index[root].Parent)
		seen := map[string]bool{}
		for hops := 0; p != "" && hops < 64 && !seen[p]; hops++ {
			if p == id {
				return true
			}
			seen[p] = true
			n, ok := index[p]
			if !ok {
				break
			}
			p = strings.ToUpper(n.Parent)
		}
	}
	return false
}
