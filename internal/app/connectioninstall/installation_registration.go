package connectioninstall

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

type registrationValue struct {
	Present bool
	Kind    uint32
	Data    []byte
}
type registrationStore interface {
	Read(string) (registrationValue, error)
	Write(string, registrationValue) error
	Remove(string) error
	Sync() error
}

var registrationNames = []string{"DisplayName", "DisplayVersion", "Publisher", "InstallLocation", "DisplayIcon", "UninstallString", "NoModify", "NoRepair", "ProductID"}

func registrationString(value string) registrationValue {
	chars := utf16.Encode([]rune(value + "\x00"))
	data := make([]byte, len(chars)*2)
	for i, c := range chars {
		binary.LittleEndian.PutUint16(data[i*2:], c)
	}
	return registrationValue{true, 1, data}
}
func registrationDWORD(value uint32) registrationValue {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, value)
	return registrationValue{true, 4, data}
}
func sameRegistrationValue(a, b registrationValue) bool {
	return a.Present == b.Present && a.Kind == b.Kind && bytes.Equal(a.Data, b.Data)
}

// Restore only the nine values we changed. Unknown values/subkeys remain intact;
// the native adapter removes a newly created key only if it is provably empty.
func writeInstallationRegistration(store registrationStore, want map[string]registrationValue) (result error) {
	old := map[string]registrationValue{}
	for _, name := range registrationNames {
		if !want[name].Present {
			return fmt.Errorf("INSTALL_REGISTRATION_PLAN_INCOMPLETE: %s", name)
		}
		value, e := store.Read(name)
		if e != nil {
			return e
		}
		old[name] = value
	}
	var changed []string
	defer func() {
		if result == nil {
			return
		}
		for i := len(changed) - 1; i >= 0; i-- {
			name := changed[i]
			var e error
			if old[name].Present {
				e = store.Write(name, old[name])
			} else {
				e = store.Remove(name)
			}
			if e != nil {
				result = errors.Join(result, fmt.Errorf("INSTALL_REGISTRATION_RESTORE_PENDING: %s: %w", name, e))
			}
		}
		if e := store.Sync(); e != nil {
			result = errors.Join(result, e)
		}
	}()
	for _, name := range registrationNames {
		// Include a failed setter too: native storage may have changed before its
		// error was returned, and the previous value must still be restored.
		changed = append(changed, name)
		if e := store.Write(name, want[name]); e != nil {
			return fmt.Errorf("INSTALL_REGISTRATION_WRITE_FAILED: %s: %w", name, e)
		}
	}
	for _, name := range registrationNames {
		got, e := store.Read(name)
		if e != nil {
			return e
		}
		if !sameRegistrationValue(got, want[name]) {
			return fmt.Errorf("INSTALL_REGISTRATION_READBACK_FAILED: %s", name)
		}
	}
	if e := store.Sync(); e != nil {
		return fmt.Errorf("INSTALL_REGISTRATION_FLUSH_FAILED: %w", e)
	}
	return nil
}
