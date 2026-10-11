package securitypolicy

import "strings"

type AccessoryKind string

const (
	KindUnknown   AccessoryKind = "unknown"
	KindHID       AccessoryKind = "hid"
	KindKeyboard  AccessoryKind = "keyboard"
	KindMouse     AccessoryKind = "mouse"
	KindNetwork   AccessoryKind = "network"
	KindStorage   AccessoryKind = "storage"
	KindHub       AccessoryKind = "hub"
	KindAudio     AccessoryKind = "audio"
	KindCamera    AccessoryKind = "camera"
	KindImaging   AccessoryKind = "imaging"
	KindMedia     AccessoryKind = "media"
	KindComposite AccessoryKind = "composite"
)

type DevicePermission string

const (
	PermissionPending DevicePermission = "pending"
	PermissionAllowed DevicePermission = "allowed"
	PermissionDenied  DevicePermission = "denied"
)

// DeviceRecord is a host-permission record, separate from USB Link's networking
// grants. Permission is user intent; Enforcement is the OS result. UI must not
// say "blocked" just because a user clicked Deny or a record was saved.
type DeviceRecord struct {
	USB              *USBConnection   `json:"usb,omitempty"` // Local display only.
	Handle           string           `json:"handle"`        // Local executor-owned handle, never an OS command/path.
	Name             string           `json:"name"`
	Kinds            []AccessoryKind  `json:"types"`
	Connected        bool             `json:"connected"`
	Permission       DevicePermission `json:"permission"`
	Enforcement      Evidence         `json:"enforcement"`
	VID              string           `json:"vid,omitempty"`
	PID              string           `json:"pid,omitempty"`
	NodeCount        int              `json:"node_count,omitempty"`
	MergedRoots      int              `json:"merged_roots,omitempty"`
	Location         string           `json:"location,omitempty"`
	DisplayKind      string           `json:"display_kind,omitempty"` // Presentation only, never an admission class.
	Description      string           `json:"description,omitempty"`
	Storage          []StorageDisk    `json:"storage,omitempty"`
	StorageProblem   string           `json:"storage_problem,omitempty"`
	NodeIDs          []string         `json:"-"` // Exact local subtree for display metadata association only.
	LastSeen         string           `json:"last_seen,omitempty"`
	FunctionsChanged bool             `json:"functions_changed"`
	PreservedInput   bool             `json:"preserved_input"`
}

type StorageDisk struct {
	Problem string          `json:"problem,omitempty"`
	Model   string          `json:"model,omitempty"`
	Bytes   uint64          `json:"bytes,omitempty"`
	Volumes []StorageVolume `json:"volumes,omitempty"`
}
type StorageVolume struct {
	Name       string `json:"name,omitempty"`
	Mount      string `json:"mount"`
	Bytes      uint64 `json:"bytes,omitempty"`
	FreeBytes  uint64 `json:"free_bytes"`
	SpaceKnown bool   `json:"space_known"`
}

// ClassifyFunctions consumes a verified device subtree. Types describe what
// Windows exposes, not whether the device is authentic or safe. A phone may
// expose storage/network/input simultaneously, so do not guess its type from a
// friendly name, manufacturer string or a single VID/PID.
func ClassifyFunctions(nodes []DeviceNode) []AccessoryKind {
	seen := map[AccessoryKind]bool{}
	for _, n := range nodes {
		switch strings.ToLower(n.ClassGUID) {
		case KeyboardClass:
			seen[KindKeyboard] = true
		case MouseClass:
			seen[KindMouse] = true
		case HIDClass:
			seen[KindHID] = true
		case "{4d36e972-e325-11ce-bfc1-08002be10318}":
			seen[KindNetwork] = true
		case "{4d36e967-e325-11ce-bfc1-08002be10318}":
			seen[KindStorage] = true
		case "{ca3e7ab9-b4c3-4ae6-8251-579ef933890f}":
			seen[KindCamera] = true
		case "{6bdd1fc6-810f-11d0-bec7-08002be2092f}":
			seen[KindImaging] = true
		case "{4d36e96c-e325-11ce-bfc1-08002be10318}":
			seen[KindMedia] = true
		}
		switch strings.ToLower(n.Service) {
		case "kbdhid":
			seen[KindKeyboard] = true
		case "mouhid":
			seen[KindMouse] = true
		case "hidusb":
			seen[KindHID] = true
		case "usbncm":
			seen[KindNetwork] = true
		case "usbstor", "uaspstor":
			seen[KindStorage] = true
		case "usbhub", "usbhub3":
			seen[KindHub] = true
		case "usbccgp":
			seen[KindComposite] = true
		}
		for _, id := range n.CompatibleIDs {
			id = strings.ToUpper(id)
			switch {
			case strings.HasPrefix(id, `USB\CLASS_03&SUBCLASS_01&PROT_01`):
				seen[KindKeyboard], seen[KindHID] = true, true
			case strings.HasPrefix(id, `USB\CLASS_03&SUBCLASS_01&PROT_02`):
				seen[KindMouse], seen[KindHID] = true, true
			case strings.HasPrefix(id, `USB\CLASS_03`):
				seen[KindHID] = true
			case strings.HasPrefix(id, `USB\CLASS_08`):
				seen[KindStorage] = true
			case strings.HasPrefix(id, `USB\CLASS_09`):
				seen[KindHub] = true
			case strings.HasPrefix(id, `USB\CLASS_01`):
				seen[KindAudio] = true
			case strings.HasPrefix(id, `USB\CLASS_0E`):
				seen[KindCamera] = true
			}
		}
	}
	var out []AccessoryKind
	for _, kind := range []AccessoryKind{KindComposite, KindKeyboard, KindMouse, KindHID, KindNetwork, KindStorage, KindHub, KindAudio, KindCamera, KindImaging, KindMedia} {
		if seen[kind] {
			out = append(out, kind)
		}
	}
	if len(out) == 0 {
		return []AccessoryKind{KindUnknown}
	}
	return out
}

type RevocationReadiness struct {
	CompleteInventory          bool
	AffectsInput               bool
	OtherVerifiedInputPath     bool
	RecoveryVerified           bool
	ExecutorSupportsRevocation bool
}

// Refuse a last-input-path revocation, even if an operator clicked the button.
// An OS-supported targeted revoke is distinct from a retroactive class ban.
func (r RevocationReadiness) CanRevoke() bool {
	return r.CompleteInventory && r.RecoveryVerified && r.ExecutorSupportsRevocation && (!r.AffectsInput || r.OtherVerifiedInputPath)
}

// USBConnection keeps declared device revision separate from observed link and
// port protocol family. Windows' cached EX/V2 APIs cannot identify exact lanes
// or distinguish USB 3.1 and 3.2 port branding.
type USBConnection struct {
	Specification string `json:"specification,omitempty"`
	Speed         string `json:"speed,omitempty"`
	PortProtocols string `json:"port_protocols,omitempty"`
}
