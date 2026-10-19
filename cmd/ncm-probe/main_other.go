//go:build (!windows || !amd64) && usblink_local_remote

package main

import "fmt"

func main() {
	fmt.Println("ncm-probe is a Windows amd64 hardware probe. Run protocol tests on Mac with go test ./internal/ncm.")
}
