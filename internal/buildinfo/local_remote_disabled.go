//go:build !windows || !amd64 || !usblink_local_remote

package buildinfo

// LocalRemote cannot be enabled by linker flags in a public build.
const LocalRemote = false
