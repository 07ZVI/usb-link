//go:build windows && amd64

package launcher

import "suhang/usbnet/internal/app/connectioninstall"

// The desktop component has its own release identity. Reusing verified bytes
// must not make the installer version select an unembedded archive name.
const bundledDesktopAsset = "assets/desktop-0.8.140.zip"

// The integrator calls these helpers from the normal/recovery launcher and
// installation cleanup. Both modes use identical embedded content identities.
func bundledDesktopDirectoryName() (string, error) {
	if !connectioninstall.DesktopStreamingEnabled() {
		b, err := payload.ReadFile(bundledDesktopAsset)
		if err != nil {
			return "", err
		}
		return connectioninstall.DesktopDirectoryName(b), nil
	}
	archive, err := macArchive(bundledDesktopAsset)
	if err != nil {
		return "", err
	}
	return connectioninstall.DesktopDirectoryNameArchive(archive.Reader, archive.Size)
}

func prepareBundledDesktop() (string, error) {
	if !connectioninstall.DesktopStreamingEnabled() {
		b, err := payload.ReadFile(bundledDesktopAsset)
		if err != nil {
			return "", err
		}
		return connectioninstall.PrepareDesktop(b)
	}
	archive, err := macArchive(bundledDesktopAsset)
	if err != nil {
		return "", err
	}
	return connectioninstall.PrepareDesktopArchive(archive.Reader, archive.Size)
}
