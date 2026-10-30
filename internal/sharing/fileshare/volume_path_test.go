package fileshare

import "testing"

func TestVolumePathsRejectOtherNamespacesAndTraversal(t *testing.T) {
	root := `\\?\Volume{12345678-1234-1234-1234-123456789abc}\`
	for _, path := range []string{root, root + `Media`, root + `資料夾\影片`} {
		if !IsVolumePath(path) || VolumeRoot(path) != root {
			t.Fatalf("valid volume path rejected: %q", path)
		}
	}
	for _, path := range []string{`D:\Media`, `\\server\Media`, `\\.\PhysicalDrive0`, `\\?\C:\Media`, `\\?\GLOBALROOT\Device\HarddiskVolume1\`, root + `..\secret`, root + `Media\..\secret`, root + `Media:stream`, root + "Media\x00", root + "/Media", `\\?\Volume{bad}\Media`} {
		if IsVolumePath(path) {
			t.Fatalf("unsafe volume path accepted: %q", path)
		}
	}
}
