package dependencies

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
)

// Readiness depends on the framework actually present, not an installer receipt.
// .NET 8/9/11 and preview-only runtimes do not satisfy the application's 10.0
// framework request; all released 10.0 patches do.
func supportsDotnet10(list string) bool {
	for _, line := range strings.Split(list, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "Microsoft.NETCore.App" {
			continue
		}
		parts := strings.Split(fields[1], ".")
		if len(parts) != 3 || parts[0] != "10" || parts[1] != "0" {
			continue
		}
		if patch, e := strconv.Atoi(parts[2]); e == nil && patch >= 0 {
			return true
		}
	}
	return false
}

// An original compatible DLL is reusable even if another installer supplied it.
// The byte pin supplies the identity; product-created receipt files are optional.
func matchingDLL(path, want string) bool {
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Size() > 8<<20 {
		return false
	}
	f, e := os.Open(path)
	if e != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, 8<<20+1))
	return e == nil && n <= 8<<20 && hex.EncodeToString(h.Sum(nil)) == want
}
