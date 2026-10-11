//go:build windows

package fileshare

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"strings"
	"sync"
	"unsafe"
)

var smbPlatform = struct {
	sync.Once
	sync.Mutex
	info map[string]any
}{}

// Read-only local inventory. It never stops services, creates accounts/shares,
// changes bindings or reads file contents. Run once outside status request I/O.
func smbPlatformInfo() any {
	smbPlatform.Once.Do(func() {
		go func() {
			info := map[string]any{}
			defer func() { smbPlatform.Lock(); smbPlatform.info = info; smbPlatform.Unlock() }()
			m, e := mgr.Connect()
			if e != nil {
				info["service_query_error"] = e.Error()
			} else {
				defer m.Disconnect()
				s, e := m.OpenService("LanmanServer")
				if e != nil {
					info["service_query_error"] = e.Error()
				} else {
					defer s.Close()
					st, e := s.Query()
					if e != nil {
						info["service_query_error"] = e.Error()
					} else {
						info["windows_server_service_state"] = uint32(st.State)
					}
				}
			}
			api := windows.NewLazySystemDLL("netapi32.dll")
			free := api.NewProc("NetApiBufferFree")
			shares := api.NewProc("NetShareEnum")
			sessions := api.NewProc("NetSessionEnum")
			for _, p := range []*windows.LazyProc{free, shares, sessions} {
				if e := p.Find(); e != nil {
					info["api_query_error"] = e.Error()
					return
				}
			}
			type shareInfo struct {
				Name   *uint16
				Type   uint32
				Remark *uint16
			}
			var buffer *shareInfo
			var read, total uint32
			rc, _, _ := shares.Call(0, 1, uintptr(unsafe.Pointer(&buffer)), uintptr(^uint32(0)), uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), 0)
			if buffer != nil {
				defer free.Call(uintptr(unsafe.Pointer(buffer)))
			}
			if rc != 0 || read > 4096 || read > 0 && buffer == nil {
				info["share_query_error"] = fmt.Sprint(rc)
			} else {

				custom := 0
				if read > 0 {
					for _, r := range unsafe.Slice(buffer, int(read)) {
						if r.Name == nil {
							continue
						}
						name := strings.ToUpper(windows.UTF16PtrToString(r.Name))
						if name == "IPC$" || name == "ADMIN$" || len(name) == 2 && name[0] >= 'A' && name[0] <= 'Z' && name[1] == '$' {
							continue
						}
						custom++
					}
				}
				info["non_default_share_count"] = custom
			}
			var sessionBuffer *byte
			read, total = 0, 0
			rc, _, _ = sessions.Call(0, 0, 0, 0, uintptr(unsafe.Pointer(&sessionBuffer)), uintptr(^uint32(0)), uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), 0)
			if sessionBuffer != nil {
				defer free.Call(uintptr(unsafe.Pointer(sessionBuffer)))
			}
			if rc == 0 {
				info["windows_smb_sessions"] = total
			} else {
				info["session_query_error"] = fmt.Sprint(rc)
			}
		}()
	})
	smbPlatform.Lock()
	defer smbPlatform.Unlock()
	out := map[string]any{"ready": smbPlatform.info != nil}
	for k, v := range smbPlatform.info {
		out[k] = v
	}
	return out
}
