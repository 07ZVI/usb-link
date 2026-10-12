//go:build windows && amd64

package connectioninstall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/platform/windows/wincom"
)

var nativeStartupEnabled atomic.Bool
var nativeStartupTriggerObservation atomic.Pointer[NativeStartupTriggerObservation]

// No task XML, account SID, command/path or requested mutation is exposed.
// Only a bounded producer observation from the last native operation is read.
func NativeStartupTriggerDetails() NativeStartupTriggerObservation {
	if observed := nativeStartupTriggerObservation.Load(); observed != nil {
		return *observed
	}
	return NativeStartupTriggerObservation{ObservationOnly: true}
}

// Cleanup reads the actual exact-owner task actions, including disabled tasks.
// Any failed identity/source/COM observation retains all previous versions.
// This entry is read-only and never starts, registers or deletes a task.
func nativeStartupDependencies(ctx context.Context, current string) ([]string, error) {
	if Verify(current) != nil {
		return nil, errors.New("STARTUP_TASK_RECEIPT_CHANGED")
	}
	name, sid, e := nativeStartupDependencyIdentity()
	if e != nil {
		return nil, e
	}
	var commands []string
	e = wincom.WithApartment(func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		scheduler, e := wincom.Create("{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}")
		if e != nil {
			return e
		}
		defer scheduler.Close()
		v, e := scheduler.Call("Connect")
		v.Clear()
		if e != nil {
			return e
		}
		folder, e := nativeObject(scheduler, "GetFolder", true, wincom.String("\\"))
		if e != nil {
			return e
		}
		defer folder.Close()
		tasks, e := nativeProductTasks(folder, name, sid)
		if e != nil {
			return e
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		for _, t := range tasks {
			commands = append(commands, t.Command)
		}
		return nil
	})
	return commands, e
}

// SetNativeStartupEnabled is selected by the protected process configuration,
// never by an arbitrary remote request. The baseline is disabled.
func SetNativeStartupEnabled(enabled bool) { nativeStartupEnabled.Store(enabled) }

func nativeStartupDependencyIdentity() (string, string, error) {
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return "", "", e
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return taskIdentity()
	}
	self, e := os.Executable()
	if e != nil {
		return "", "", e
	}
	binding, e := ActivateCoreOwner(self)
	if e != nil || !sidPattern.MatchString(binding.OwnerSID) {
		return "", "", errors.New("STARTUP_TOKEN_UNAVAILABLE")
	}
	h := sha256.Sum256([]byte(binding.OwnerSID))
	return "USB-Link-" + hex.EncodeToString(h[:8]), binding.OwnerSID, nil
}

func nativeString(d *wincom.Dispatch, n string) (string, error) {
	v, e := d.Get(n)
	if e != nil {
		return "", e
	}
	defer v.Clear()
	return v.String()
}
func nativeInt(d *wincom.Dispatch, n string) (int32, error) {
	v, e := d.Get(n)
	if e != nil {
		return 0, e
	}
	defer v.Clear()
	return v.Int()
}
func nativeBool(d *wincom.Dispatch, n string) (bool, error) {
	v, e := d.Get(n)
	if e != nil {
		return false, e
	}
	defer v.Clear()
	return v.Bool()
}
func nativeObject(d *wincom.Dispatch, n string, method bool, a ...wincom.Value) (*wincom.Dispatch, error) {
	var v wincom.Value
	var e error
	if method {
		v, e = d.Call(n, a...)
	} else {
		v, e = d.Get(n, a...)
	}
	if e != nil {
		return nil, e
	}
	defer v.Clear()
	return v.Dispatch()
}
func nativeExactSID(s string) (string, error) {
	if strings.HasPrefix(s, "S-") {
		v, e := windows.StringToSid(s)
		if e != nil || !v.IsValid() {
			return "", errors.New("STARTUP_PRINCIPAL_CHANGED")
		}
		return v.String(), nil
	}
	v, _, _, e := windows.LookupSID("", s)
	if e != nil {
		return "", errors.New("STARTUP_PRINCIPAL_CHANGED")
	}
	return v.String(), nil
}

func nativeProductTasks(folder *wincom.Dispatch, name, sid string) ([]nativeStartupTask, error) {
	return nativeProductTasksVerified(folder, name, sid, Verify, true)
}
func nativeProductTasksVerified(folder *wincom.Dispatch, name, sid string, verify func(string) error, recordObservation bool) ([]nativeStartupTask, error) {
	return nativeProductTasksInspected(folder, name, sid, verify, recordObservation, false)
}

func nativeProductTasksInspected(folder *wincom.Dispatch, name, sid string, verify func(string) error, recordObservation, collectErrors bool) ([]nativeStartupTask, error) {
	c, e := nativeObject(folder, "GetTasks", true, wincom.Int(1))
	if e != nil {
		return nil, e
	}
	defer c.Close()
	count, e := nativeInt(c, "Count")
	if e != nil {
		return nil, e
	}
	if count < 0 || count > 4096 {
		return nil, errors.New("STARTUP_QUERY_UNBOUNDED")
	}
	legacy := strings.Replace(name, "USB-Link-", "Suhang-iPad-USB-", 1)
	out := []nativeStartupTask{}
	var problems []error
	for i := int32(1); i <= count; i++ {
		item, e := nativeObject(c, "Item", false, wincom.Int(i))
		if e != nil {
			return nil, e
		}
		t, e := func() (nativeStartupTask, error) {
			defer item.Close()
			t := nativeStartupTask{}
			var e error
			t.Name, e = nativeString(item, "Name")
			if e != nil {
				return t, e
			}
			if !strings.EqualFold(t.Name, name) && !strings.EqualFold(t.Name, legacy) {
				return t, nil
			}
			t.Path, e = nativeString(item, "Path")
			if e != nil {
				return t, e
			}
			if (t.Name != name && t.Name != legacy) || t.Path != "\\"+t.Name {
				return t, errors.New("STARTUP_TASK_OWNERSHIP_CHANGED")
			}
			t.XML, e = nativeString(item, "Xml")
			if e != nil {
				return t, e
			}
			t.State, e = nativeInt(item, "State")
			if e != nil {
				return t, e
			}
			t.Enabled, e = nativeBool(item, "Enabled")
			if e != nil {
				return t, e
			}
			parsed, err := parseNativeStartupTask(t, sid, nativeExactSID, verify)
			if recordObservation && parsed.TriggerObservation != nil {
				copy := *parsed.TriggerObservation
				nativeStartupTriggerObservation.Store(&copy)
			}
			return parsed, err
		}()
		if e != nil {
			// Inspection may retain the failed object's identity for diagnostics;
			// operational callers must still reject the non-nil error.
			t.InspectionProblem = e.Error()
			if !collectErrors {
				return append(out, t), e
			}
			out = append(out, t)
			problems = append(problems, fmt.Errorf("%s: %w", t.Name, e))
			continue
		}
		if strings.EqualFold(t.Name, name) || strings.EqualFold(t.Name, legacy) {
			for _, old := range out {
				if strings.EqualFold(t.Name, old.Name) {
					return nil, errors.New("STARTUP_TASK_AMBIGUOUS")
				}
			}
			out = append(out, t)
		}
	}
	return out, errors.Join(problems...)
}

func runNativeStartupTask(ctx context.Context, mode, path, name, sid, xmlText string) (result StartupTaskObservation, err error) {
	nativeStartupTriggerObservation.Store(nil)
	result = StartupTaskObservation{Code: "STARTUP_QUERY_FAILED", Phase: "QUERY", Operation: "QUERY", ExceptionKind: "NONE", InnerExceptionKind: "NONE"}
	err = wincom.WithApartment(func() error {
		if e := ctx.Err(); e != nil {
			return errors.New("STARTUP_CANCELLED")
		}
		if mode == "ON" {
			result.Phase = "REGISTER"
			result.Operation = "CONNECT"
		}
		scheduler, e := wincom.Create("{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}")
		if e != nil {
			return e
		}
		defer scheduler.Close()
		v, e := scheduler.Call("Connect")
		v.Clear()
		if e != nil {
			return e
		}
		if mode == "ON" {
			result.Operation = "ROOT_FOLDER"
		}
		folder, e := nativeObject(scheduler, "GetFolder", true, wincom.String("\\"))
		if e != nil {
			return e
		}
		defer folder.Close()
		result.Phase = "QUERY"
		result.Operation = "QUERY"
		tasks, e := nativeProductTasks(folder, name, sid)
		if e != nil {
			return e
		}
		register := func(flags int32) error {
			if e := ctx.Err(); e != nil {
				return errors.New("STARTUP_CANCELLED")
			}
			v, e := folder.Call("RegisterTask", wincom.String(name), wincom.String(xmlText), wincom.Int(flags), wincom.String(sid), wincom.Null(), wincom.Int(3), wincom.Null())
			v.Clear()
			return e
		}
		remove := func(t nativeStartupTask) error {
			if e := ctx.Err(); e != nil {
				return errors.New("STARTUP_CANCELLED")
			}
			fresh, e := nativeProductTasks(folder, name, sid)
			if e != nil {
				return e
			}
			matched := false
			for _, f := range fresh {
				if f.Name == t.Name {
					matched = true
				}
			}
			if !matched {
				return errors.New("STARTUP_READBACK_CHANGED")
			}
			v, e := folder.Call("DeleteTask", wincom.String(t.Name), wincom.Int(0))
			v.Clear()
			return e
		}
		if mode == "ON" {
			result.Phase = "REGISTER"
			result.Operation = "VALIDATE_XML"
			if e = register(1); e != nil {
				return e
			}
			result.Operation = "PREWRITE"
			fresh, e := nativeProductTasks(folder, name, sid)
			if e != nil {
				return e
			}
			flags := int32(2)
			result.Operation = "CREATE"
			for _, t := range fresh {
				if t.Name == name {
					flags = 4
					result.Operation = "UPDATE"
				}
			}
			if e = register(flags); e != nil {
				return e
			}
			result.Phase = "READBACK"
			result.Operation = "READBACK"
			fresh, e = nativeProductTasks(folder, name, sid)
			if e != nil {
				return e
			}
			current := 0
			for _, t := range fresh {
				if t.Name == name && t.Enabled && strings.EqualFold(filepath.Clean(t.Command), filepath.Clean(path)) {
					current++
				}
			}
			if current != 1 {
				return errors.New("STARTUP_READBACK_CHANGED")
			}
			result.Phase = "REMOVE"
			result.Operation = "REMOVE"
			for _, t := range tasks {
				if t.Name != name {
					if e = remove(t); e != nil {
						return e
					}
				}
			}
		} else if mode == "OFF" {
			result.Phase = "REMOVE"
			result.Operation = "REMOVE"
			for _, t := range tasks {
				if e = remove(t); e != nil {
					return e
				}
			}
		}
		result.Phase = "READBACK"
		result.Operation = "READBACK"
		final, e := nativeProductTasks(folder, name, sid)
		if e != nil {
			return e
		}
		result.TaskCount = len(final)
		for _, t := range final {
			result.Enabled = result.Enabled || t.Enabled
		}
		if mode == "ON" && (len(final) != 1 || final[0].Name != name || !final[0].Enabled || !strings.EqualFold(filepath.Clean(final[0].Command), filepath.Clean(path))) {
			return errors.New("STARTUP_READBACK_CHANGED")
		}
		if mode == "OFF" && len(final) != 0 {
			return errors.New("STARTUP_READBACK_CHANGED")
		}
		result.Available = true
		result.Code = "OK"
		return nil
	})
	if err != nil {
		result.Available = false
		result.Enabled = false
		result.TaskCount = 0
		result.ExceptionKind = "OTHER"
		result.ExceptionDepth = 1
		result.Code = "STARTUP_" + result.Phase + "_FAILED"
		if startupFailureCode(err.Error()) {
			result.Code = err.Error()
		}
		var ce *wincom.Error
		if errors.As(err, &ce) {
			result.NativeError = ce.HRESULT
			result.ExceptionKind = "COM"
		}
		err = errors.New(result.Code)
	}
	return result, err
}
