//go:build !windows || !amd64

package bridgeworker

import "fmt"

func Main() { fmt.Println("suhang-usbnet is a Windows amd64 USB/Wintun bridge.") }
