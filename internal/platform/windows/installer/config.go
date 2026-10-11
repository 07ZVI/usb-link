package installer

import (
	"fmt"
	"strings"
)

// ZadigConfig uses the quoted-string syntax of official profile.c, which
// consumes backslashes even before unrecognized escape letters.
func ZadigConfig(driverDir string) (string, error) {
	if driverDir == "" || strings.ContainsAny(driverDir, "\x00\r\n\t\b") {
		return "", fmt.Errorf("invalid driver extraction directory")
	}
	quoted := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(driverDir)
	return "[general]\nadvanced_mode=true\nexit_on_success=false\nlog_level=1\n[device]\nlist_all=true\ninclude_hubs=false\ntrim_whitespaces=true\n[driver]\ndefault_driver=0\nextract_only=true\ndefault_dir=\"" + quoted + "\"\n", nil
}
