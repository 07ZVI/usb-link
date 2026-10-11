package connectioninstall

import "os"

// Default off. This changes resource preparation only, never release trust,
// signed upgrade policy, installed bytes, or desktop content identity.
func DesktopStreamingEnabled() bool { return os.Getenv("SUHANG_DESKTOP_STREAMING") == "1" }
