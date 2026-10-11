package bridge

// SessionVersion is the ownership journal format, independent of release numbers.
// Keep it stable unless the journal fields or their semantics change.
const SessionVersion = "0.7.0-phase02"
const RetainedSessionVersion = "0.8.98-retained-address"

// A resident session token identifies only a held live bridge lease. It never
// names firewall rules or authorizes removal of permanent rule receipts.
const ResidentSessionVersion = "0.8.109-resident-firewall"

type OwnedSession struct {
	Version  string           `json:"version"`
	GUID     string           `json:"guid"`
	Token    string           `json:"token"`
	Status   string           `json:"status"`
	Retained *RetainedAddress `json:"retained_address,omitempty"`
}

func NewOwnedSession(guid, token string) OwnedSession {
	return OwnedSession{Version: SessionVersion, GUID: guid, Token: token, Status: "ACTIVE"}
}

// This metadata is not authorization: recovery must re-read the protected
// originals and complete exact native identity/address proof before reuse.
type RetainedAddress struct {
	Index         uint32 `json:"index"`
	LUID          uint64 `json:"luid"`
	Created       int64  `json:"created"`
	Mode          string `json:"mode"`
	ReceiptSHA256 string `json:"receipt_sha256"`
	Prepared      bool   `json:"network_prepared"`
}
