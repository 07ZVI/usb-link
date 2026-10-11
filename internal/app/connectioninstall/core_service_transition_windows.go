//go:build windows && amd64

package connectioninstall

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"os"
	"path/filepath"
	"time"
	"unsafe"
)

const coreTransitionFile = "core-service-transition.json"

func readCoreTransition() (coreServiceTransition, bool, error) {
	var t coreServiceTransition
	root, e := protectedRoot(false)
	if e != nil {
		return t, false, e
	}
	b, e := coreProtectedRead(filepath.Join(root, coreTransitionFile), false, true)
	if os.IsNotExist(e) || e == windows.ERROR_FILE_NOT_FOUND {
		return t, false, nil
	}
	if e != nil {
		return t, false, e
	}
	t, e = parseCoreTransition(b)
	if e != nil {
		return t, true, e
	}
	for _, v := range []*CoreServiceBinding{t.Previous, &t.Next} {
		if v == nil {
			continue
		}
		hash, e := fileHash(v.Executable)
		if VerifyCoreExecutable(v.Executable) != nil || e != nil || hash != v.SHA256 {
			return t, true, fmt.Errorf("CORE_SERVICE_TRANSITION_SOURCE_CHANGED")
		}
	}
	return t, true, nil
}
func writeCoreTransition(t coreServiceTransition) error {
	_, found, e := readCoreTransition()
	if e != nil || found {
		return fmt.Errorf("CORE_SERVICE_TRANSITION_PENDING")
	}
	root, e := protectedRoot(false)
	if e != nil {
		return e
	}
	b, e := json.Marshal(t)
	if e != nil || len(b) > 4096 {
		return fmt.Errorf("CORE_SERVICE_TRANSITION_INVALID")
	}
	sd, e := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	path := filepath.Join(root, coreTransitionFile)
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.GENERIC_READ|windows.GENERIC_WRITE, 0, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return fmt.Errorf("CORE_SERVICE_TRANSITION_WRITE_FAILED")
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return fmt.Errorf("CORE_SERVICE_TRANSITION_WRITE_FAILED")
	}
	got, found, e := readCoreTransition()
	if e != nil || !found || !equalCoreTransition(got, t) {
		return fmt.Errorf("CORE_SERVICE_TRANSITION_READBACK_FAILED")
	}
	return nil
}
func equalCoreTransition(a, b coreServiceTransition) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func clearCoreTransition(t coreServiceTransition) error {
	got, present, e := readCoreTransition()
	if e != nil || !present || !equalCoreTransition(got, t) {
		return fmt.Errorf("CORE_SERVICE_TRANSITION_CHANGED")
	}
	root, _ := Root()
	if e = os.Remove(filepath.Join(root, coreTransitionFile)); e != nil {
		return e
	}
	_, present, e = readCoreTransition()
	if e != nil || present {
		return fmt.Errorf("CORE_SERVICE_TRANSITION_NOT_CLEARED")
	}
	return nil
}
func recoverCoreServiceTransition() error {
	t, present, e := readCoreTransition()
	if e != nil || !present {
		return e
	}
	binding, bound, e := readCoreBinding()
	if e != nil {
		return e
	}
	if bound && binding != t.Next && (t.Previous == nil || binding != *t.Previous) {
		return fmt.Errorf("CORE_SERVICE_TRANSITION_BINDING_CHANGED")
	}
	if !bound && t.Previous != nil {
		return fmt.Errorf("CORE_SERVICE_TRANSITION_OLD_BINDING_MISSING")
	}
	m, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer m.Disconnect()
	s, e := m.OpenService(CoreServiceName)
	missing := e == windows.ERROR_SERVICE_DOES_NOT_EXIST
	if e != nil && !missing {
		return e
	}
	if !missing {
		defer func() {
			if s != nil {
				s.Close()
			}
		}()
		c, e := s.Config()
		args, ae := windows.DecomposeCommandLine(c.BinaryPathName)
		isNext := e == nil && ae == nil && validateCoreServiceConfig(t.Next.Executable, c.ServiceStartName, c.ServiceType, c.StartType, c.DelayedAutoStart, args) == nil
		isOld := t.Previous != nil && e == nil && ae == nil && validateCoreServiceConfig(t.Previous.Executable, c.ServiceStartName, c.ServiceType, c.StartType, c.DelayedAutoStart, args) == nil
		if !isNext && !isOld || coreServiceSecurity(s) != nil || coreServiceExecutionPolicy(s, c) != nil {
			return fmt.Errorf("CORE_SERVICE_TRANSITION_CONFIG_CHANGED")
		}
		if e = stopCore(s); e != nil {
			return e
		}
		if t.Previous != nil {
			c.BinaryPathName = windows.ComposeCommandLine([]string{t.Previous.Executable, CoreServiceArgument})
			if e = s.UpdateConfig(c); e != nil {
				return e
			}
		} else {
			if e = s.Delete(); e != nil {
				return e
			}
			s.Close()
			s = nil
			end := time.Now().Add(10 * time.Second)
			for {
				q, qe := m.OpenService(CoreServiceName)
				if qe == windows.ERROR_SERVICE_DOES_NOT_EXIST {
					break
				}
				if qe == nil {
					q.Close()
				} else if qe != windows.ERROR_SERVICE_MARKED_FOR_DELETE {
					return qe
				}
				if time.Now().After(end) {
					return fmt.Errorf("CORE_SERVICE_TRANSITION_DELETE_PENDING")
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	} else if t.Previous != nil {
		return fmt.Errorf("CORE_SERVICE_TRANSITION_OLD_SERVICE_MISSING")
	}
	// Compare the exact durable transition again before restoring/removing only
	// its known binding. A foreign update never gets overwritten by rollback.
	got, found, e := readCoreTransition()
	if e != nil || !found || !equalCoreTransition(got, t) {
		return fmt.Errorf("CORE_SERVICE_TRANSITION_CHANGED")
	}
	if t.Previous != nil {
		if binding != *t.Previous {
			if e = writeCoreBinding(*t.Previous, &binding); e != nil {
				return e
			}
		}
		verified, b, e := ownedCoreService(m)
		if e != nil {
			return e
		}
		verified.Close()
		if b != *t.Previous {
			return fmt.Errorf("CORE_SERVICE_ROLLBACK_UNCONFIRMED")
		}
	} else if bound {
		fresh, present, e := readCoreBinding()
		if e != nil || !present || fresh != binding {
			return fmt.Errorf("CORE_SERVICE_TRANSITION_BINDING_CHANGED")
		}
		root, _ := Root()
		if e = os.Remove(filepath.Join(root, coreBindingFile)); e != nil {
			return e
		}
	}
	if e = clearCoreTransition(t); e != nil {
		return e
	}
	// The caller owns migration/uninstall and decides when to release recovery
	// locks and start the restored service; rollback never starts a parallel core.
	return nil
}
