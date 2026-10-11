//go:build windows && amd64

package launcher

import _ "embed"

//go:embed assets/usb-resource-0.8.140.exe
var resourceObserver []byte
