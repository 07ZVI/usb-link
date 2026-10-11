package interfaceconfig

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestOwnedDADObservationHasNoPrivateIdentityOrVerifiedAuthority(t *testing.T) {
	original := testOwnedDAD().Originals[0]
	original.Identity.Instance = "PRIVATE_NODE"
	original.Identity.RootInstance = "PRIVATE_ROOT"
	original.Identity.Driver = "PRIVATE_DRIVER"
	original.Identity.Serial = "PRIVATE_SERIAL"
	v := ownedDADObservation(original)
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	for _, private := range []string{"PRIVATE_NODE", "PRIVATE_ROOT", "PRIVATE_DRIVER", "PRIVATE_SERIAL", "verified", "instance", "root_instance", "driver", "serial", "path"} {
		if strings.Contains(string(b), private) {
			t.Fatalf("private/authorization field exported: %s", b)
		}
	}
	if !v.ObservationOnly || v.Scope != "MAPPING_READ_ONLY_NOT_OWNERSHIP" || v.CurrentDadTransmits != nil || v.CurrentIndex != nil || v.CurrentLUID != nil || v.Code != "NATIVE_UNOBSERVED" || v.OriginalDadTransmits != 3 {
		t.Fatal(v)
	}
}
func TestOwnedDADObservationSourceCannotMutateOrRecover(t *testing.T) {
	b, e := os.ReadFile("owned_dad_observation_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, forbidden := range []string{"setInterface.Call", "SetIpInterfaceEntry(", "setOwnedDad(", "writeOwnedDADFile(", "clearOwnedDADFile(", "RetireOwnedDADAbsent(", "RestoreOwnedDAD", "ApplyOwnedDAD", "verifyOwner(", "lockConfig(", "Mkdir", "CreateMutex", "CreateFile("} {
		if strings.Contains(s, forbidden) {
			t.Fatal("readonly contract broken", forbidden)
		}
	}
	for _, required := range []string{"readOwnedDADFile(dir)", "table.NumEntries > 65536", "READ_ONLY_MAPPING_NOT_OWNERSHIP", "NATIVE_MAPPING_ABSENT_NOT_FULL_ABSENCE_PROOF", "NATIVE_MAPPING_CHANGED_DURING_READ"} {
		if !strings.Contains(s, required) {
			t.Fatal("read/privacy bound missing", required)
		}
	}
}
