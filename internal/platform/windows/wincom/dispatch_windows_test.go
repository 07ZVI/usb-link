//go:build windows && amd64

package wincom

import (
	"testing"
	"unsafe"
)

func TestAutomationABI(t *testing.T) {
	if unsafe.Sizeof(rawVariant{}) != 24 || unsafe.Sizeof(dispatchParams{}) != 24 || unsafe.Sizeof(exceptionInfo{}) != 64 {
		t.Fatal("OleAutomation ABI")
	}
	if unsafe.Offsetof(exceptionInfo{}.SCode) != 56 {
		t.Fatal("EXCEPINFO layout")
	}
}
func TestAutomationTypedScalars(t *testing.T) {
	a := ArrayStrings([]string{"one"})
	got, e := a.Strings(1)
	if e != nil || len(got) != 1 || got[0] != "one" {
		t.Fatal(got, e)
	}
	values, e := a.Values(1)
	if e != nil || len(values) != 1 {
		t.Fatal(e)
	}
	if text, e := values[0].String(); e != nil || text != "one" {
		t.Fatal(text, e)
	}
	if _, e := a.Strings(0); e == nil {
		t.Fatal("constructor array unbounded")
	}
	if n, e := Int(-1).Int(); e != nil || n != -1 {
		t.Fatal(n, e)
	}
	if _, e := UInt(0xffffffff).Int(); e == nil {
		t.Fatal("unsigned overflow")
	}
	if n, e := UInt(0xffffffff).UInt(); e != nil || n != 0xffffffff {
		t.Fatal(n, e)
	}
	if _, e := Null().String(); e == nil {
		t.Fatal("null is not empty string")
	}
	if _, e := (Value{raw: rawVariant{VT: 11, Data: 1}}).Bool(); e == nil {
		t.Fatal("noncanonical boolean")
	}
}
func TestAutomationNativeStringsAndArrays(t *testing.T) {
	if e := WithApartment(func() error {
		v, c, e := String("你好🙂").native()
		if e != nil {
			return e
		}
		defer c()
		x := Value{raw: v}
		s, e := x.String()
		if e != nil || s != "你好🙂" {
			t.Fatalf("BSTR %q %v", s, e)
		}
		r, clear, e := ArrayStrings([]string{"USB Link", "你好"}).native()
		if e != nil {
			return e
		}
		defer clear()
		a := Value{raw: r}
		got, e := a.Strings(2)
		if e != nil || len(got) != 2 || got[1] != "你好" {
			t.Fatalf("array %v %v", got, e)
		}
		if _, e := a.Strings(1); e == nil {
			t.Fatal("unbounded array")
		}
		values, e := a.Values(2)
		if e != nil {
			return e
		}
		for i := range values {
			defer values[i].Clear()
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
