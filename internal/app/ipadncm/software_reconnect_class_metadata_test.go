package ipadncm

import (
	"reflect"
	"testing"
)

func TestClassMetadataHasOnlyFixedGUIDStringsAndIntegerDimensions(t *testing.T) {
	typ := reflect.TypeOf(SoftwareReconnectNativeObservation{})
	for name, expected := range map[string]reflect.Kind{"CMClassGUID": reflect.String, "SetupClassGUID": reflect.String, "ExpectedClassGUID": reflect.String, "ClassPropertyType": reflect.Uint32, "ClassPropertySize": reflect.Uint32} {
		field, ok := typ.FieldByName(name)
		if !ok || field.Type.Kind() != expected {
			t.Fatal("class diagnostic type changed", name)
		}
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.Type.Kind() == reflect.String && field.Name != "Error" && field.Name != "CMClassGUID" && field.Name != "SetupClassGUID" && field.Name != "ExpectedClassGUID" {
			t.Fatal("unexpected raw string in native observation", field.Name)
		}
	}
}

func TestClassMetadataCannotOverrideFailedFixedClassProof(t *testing.T) {
	j := softwareJournalFixture()
	s := enabledSoftwareObservation(j)
	s.ExactClass = false
	s.CMClassGUID, s.SetupClassGUID, s.ExpectedClassGUID = softwareReconnectRootClass, softwareReconnectRootClass, softwareReconnectRootClass
	s.ClassPropertyType, s.ClassPropertySize = 13, 16
	if s.owned(j) || s.enabled(j) || s.disabled(j) {
		t.Fatal("diagnostic class values substituted for native admission proof")
	}
}
