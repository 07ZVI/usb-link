//go:build !windows

package fileshare

func smbPlatformInfo() any { return nil }
