package interfaceconfig

import (
	"errors"
	"strings"
)

func validateDADFactoryOriginal(original Scope, current Scope, sha string, persistent persistentOriginal, dad dadOriginal, value uint32) error {
	if validateScope(original) != nil || validateScope(current) != nil || (original.Role != "host" && original.Role != "mac") || current.Role != original.Role || !strings.EqualFold(current.GUID, original.GUID) || dad.Scope != original || dad.Original > 32 || persistent.Scope.Role != original.Role || !strings.EqualFold(persistent.Scope.GUID, original.GUID) || persistentDigest(persistent) != sha || persistent.AppliedAddress == nil || persistent.Profile == nil || (value != 0 && value != dad.Original) {
		return errors.New("USB_DAD_FACTORY_ORIGINAL_UNPROVEN")
	}
	return nil
}

func validateDADProjection(original, current Scope) error {
	if validateScope(original) != nil || validateScope(current) != nil || original.LUID != current.LUID || (original.Role != "host" && original.Role != "mac") || current.Role != original.Role || !strings.EqualFold(current.GUID, original.GUID) {
		return errors.New("USB_DAD_PROJECTION_LUID_CHANGED")
	}
	return nil
}
