//go:build windows && amd64 && !usblink_local_remote

package ipadncm

func handleLocalRemoteAction(*modernUI, desktopRequest) bool { return false }
func localDeveloperDebugStatus() any                         { return nil }

// DeveloperDebugDiagnostics exposes only cached state, never credentials.
func DeveloperDebugDiagnostics() any { return localDeveloperDebugStatus() }
