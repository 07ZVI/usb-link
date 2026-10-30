package fileshare

import (
	"regexp"
	"strings"
)

var volumePathPattern = regexp.MustCompile(`(?i)^\\\\\?\\Volume\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}\\`)

// Only a local volume GUID namespace is accepted, never arbitrary device paths.
func IsVolumePath(path string) bool {
	root := volumePathPattern.FindString(path)
	if root == "" || strings.ContainsAny(path[len(root):], ":/\x00\r\n") {
		return false
	}
	for _, part := range strings.Split(path[len(root):], `\`) {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func VolumeRoot(path string) string { return volumePathPattern.FindString(path) }
