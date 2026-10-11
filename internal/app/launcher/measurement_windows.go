//go:build windows && amd64

package launcher

import _ "embed"

//go:embed assets/usb-resource.exe
var resourceObserver []byte
