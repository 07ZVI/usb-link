package fileshare

import (
	"sync"
	"time"
)

type SMBOperation struct {
	Command uint16 `json:"command"`
	Status  uint32 `json:"status"`
}
type SMBTrace struct {
	Accepted    uint64         `json:"accepted_tcp"`
	Active      uint64         `json:"active_tcp"`
	Rejected    uint64         `json:"rejected_tcp"`
	Commands    uint64         `json:"commands"`
	LastAttempt string         `json:"last_attempt_utc,omitempty"`
	Recent      []SMBOperation `json:"recent_operations"`
}

var smbTrace = struct {
	sync.Mutex
	peers map[string]*SMBTrace
}{peers: map[string]*SMBTrace{}}

func smbRecord(peer string, update func(*SMBTrace)) {
	if peer != "10.6.9.2" && peer != "10.6.9.3" {
		return
	}
	smbTrace.Lock()
	defer smbTrace.Unlock()
	v := smbTrace.peers[peer]
	if v == nil {
		v = &SMBTrace{}
		smbTrace.peers[peer] = v
	}
	update(v)
}
func smbObserve(peer string, command uint16, status uint32) {
	smbRecord(peer, func(v *SMBTrace) {
		v.Commands++
		// Payload traffic is counted but not stored, so transfers do not obscure
		// negotiation/discovery failures or expose names, contents or credentials.
		if command == 8 || command == 9 {
			return
		}
		if len(v.Recent) == 12 {
			copy(v.Recent, v.Recent[1:])
			v.Recent = v.Recent[:11]
		}
		v.Recent = append(v.Recent, SMBOperation{command, status})
	})
}
func SMBDiagnostics(peer string) any {
	smbTrace.Lock()
	defer smbTrace.Unlock()
	var trace SMBTrace
	if v := smbTrace.peers[peer]; v != nil {
		trace = *v
		trace.Recent = append([]SMBOperation(nil), v.Recent...)
	}
	return map[string]any{"enabled": USB.Enabled.Load(), "connect_url": SMBConnectURL(), "protocol": map[bool]string{false: "SMB2/3 over admitted USB peer", true: "Windows native SMB on TCP 445"}[USB.Native.Load()], "trace": trace, "platform": smbPlatformInfo()}
}
func smbConnection(peer string) func() {
	smbRecord(peer, func(v *SMBTrace) { v.Accepted++; v.Active++; v.LastAttempt = time.Now().UTC().Format(time.RFC3339) })
	return func() {
		smbRecord(peer, func(v *SMBTrace) {
			if v.Active > 0 {
				v.Active--
			}
		})
	}
}
