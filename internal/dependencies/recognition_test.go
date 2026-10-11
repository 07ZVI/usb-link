package dependencies

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestInstalledRuntimeCompatibilityWithoutProductReceipt(t *testing.T) {
	for _, c := range []struct {
		list string
		want bool
	}{
		{"Microsoft.NETCore.App 10.0.0 [C:\\dotnet\\shared]", true},
		{"Microsoft.NETCore.App 10.0.99 [D:\\Microsoft\\dotnet\\shared]", true},
		{"Microsoft.WindowsDesktop.App 10.0.12 [C:\\dotnet\\shared]\nMicrosoft.NETCore.App 10.0.12 [C:\\dotnet\\shared]", true},
		{"Microsoft.NETCore.App 8.0.12 [C:\\dotnet\\shared]", false},
		{"Microsoft.NETCore.App 11.0.0 [C:\\dotnet\\shared]", false},
		{"Microsoft.NETCore.App 10.0.0-preview.1 [C:\\dotnet\\shared]", false},
		{"Microsoft.NETCore.AppFake 10.0.12 [C:\\dotnet\\shared]", false},
	} {
		if got := supportsDotnet10(c.list); got != c.want {
			t.Fatalf("%q: got %t want %t", c.list, got, c.want)
		}
	}
}

func TestExternalDLLIdentityDoesNotRequireProductReceipt(t *testing.T) {
	data := []byte("compatible DLL fixture installed by someone else")
	h := sha256.Sum256(data)
	path := filepath.Join(t.TempDir(), "wintun.dll")
	if e := os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	if !matchingDLL(path, hex.EncodeToString(h[:])) {
		t.Fatal("valid external DLL required a product receipt")
	}
	os.WriteFile(path, []byte("incompatible DLL"), 0600)
	if matchingDLL(path, hex.EncodeToString(h[:])) {
		t.Fatal("filename substituted for compatible DLL identity")
	}
}
