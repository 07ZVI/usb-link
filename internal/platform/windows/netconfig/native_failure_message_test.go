package netconfig

import (
	"strings"
	"testing"
)

func TestNativeFailureMessageIsStrictBoundedAndNumericOnly(t *testing.T) {
	source := nativeStep(nil, "mac_address", func() error { return testCOMFailure(0x80041008) })
	b, ok := NativeStepFailureMessage(source)
	if !ok || strings.Contains(string(b), "private") {
		t.Fatal("unsafe/missing message", string(b))
	}
	v, e := DecodeNativeStepFailureMessage(b)
	if e != nil || v.Operation != "mac_address" || v.HRESULT != 0x80041008 {
		t.Fatal(v, e)
	}
	for _, bad := range []string{
		strings.Replace(string(b), `"schema":1`, `"schema":1,"schema":1`, 1),
		strings.Replace(string(b), `"hresult":2147749896`, `"hresult":2147749896,"hresult":2147749896`, 1),
		strings.Replace(string(b), `"hresult":2147749896`, `"hresult":null`, 1),
		strings.Replace(string(b), `"operation":"mac_address"`, `"operation":"private path"`, 1),
		strings.Replace(string(b), `"hresult":2147749896`, `"hresult":5`, 1),
		strings.Replace(string(b), `"hresult":2147749896`, `"hresult":4294967296`, 1),
		strings.Replace(string(b), `"schema":1`, `"schema":2`, 1),
		strings.Replace(string(b), `"schema":1`, `"schema":1,"path":"secret"`, 1),
		string(b) + "{}", strings.Repeat(" ", 513),
	} {
		if _, e := DecodeNativeStepFailureMessage([]byte(bad)); e == nil {
			t.Fatal("malformed accepted", bad)
		}
	}
}
