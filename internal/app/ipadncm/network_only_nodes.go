package ipadncm

import (
	"strings"
	"suhang/usbnet/internal/transport/ipadsession"
)

const portableWPDClass = "{eec5ad98-8080-425f-922a-dabf3de3f69a}"
const portableImageClass = "{6bdd1fc6-810f-11d0-bec7-08002be2092f}"

type portableNodeReceipt struct {
	Root             string `json:"device_root"`
	ID               string `json:"node_id"`
	Class            string `json:"class_guid"`
	OriginalDisabled bool   `json:"original_disabled"`
	ConfigFlags      uint32 `json:"original_config_flags"`
}

func portableClass(class string) bool {
	return strings.EqualFold(class, portableWPDClass) || strings.EqualFold(class, portableImageClass)
}
func validPortableReceipt(n portableNodeReceipt) bool {
	return ipadsession.USBGrant(n.Root, "12AB", "network-only-scope").Valid() && n.ID != "" && len(n.ID) <= 1024 && !strings.EqualFold(n.ID, n.Root) && !strings.ContainsAny(n.ID, "\x00\r\n") && portableClass(n.Class) && (n.ConfigFlags&1 == 0 || n.OriginalDisabled)
}

// Disabled (4), Boot (0), and System (1) are preserved; only Automatic (2)
// becomes Manual (3). This never relaxes an existing disabled service.
func networkOnlyServiceStartType(original uint32) uint32 {
	if original == 2 {
		return 3
	}
	return original
}

func portableNodePrefix(id string) string {
	parts := strings.SplitN(id, `\`, 3)
	if len(parts) >= 2 {
		return parts[0] + `\` + parts[1]
	}
	return "INVALID_NODE_PREFIX"
}
