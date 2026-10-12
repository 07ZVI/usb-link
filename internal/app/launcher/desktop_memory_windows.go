//go:build windows && amd64

package launcher

import (
	"bytes"
	"context"
	"errors"
	"suhang/usbnet/internal/app/connectioninstall"
)

func checkBundledInstallation() (bool, error) {
	archive, payloadError := macArchive(bundledDesktopAsset)
	if payloadError == nil {
		payloadError = connectioninstall.ValidateInstallationPayload(version, archive.Reader, archive.Size)
	}
	cleanup, stateError := connectioninstall.PlanLocalInstallationForSetup(version)
	return cleanup, errors.Join(payloadError, stateError)
}

// Embedded bytes remain the verification authority. Release numbers select
// readable folders only; they cannot authorize changed or foreign UI files.
const bundledDesktopAsset = "assets/desktop.zip"

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
		return connectioninstall.PrepareDesktopVersion(bytes.NewReader(b), int64(len(b)), version)
	}
	archive, err := macArchive(bundledDesktopAsset)
	if err != nil {
		return "", err
	}
	return connectioninstall.PrepareDesktopVersion(archive.Reader, archive.Size, version)
}

// Setup stages the complete immutable UI before stopping the previous core.
func installBundledRelease(ctx context.Context) (string, error) {
	if !connectioninstall.DesktopStreamingEnabled() {
		b, e := payload.ReadFile(bundledDesktopAsset)
		if e != nil {
			return "", e
		}
		return connectioninstall.InstallRelease(ctx, version, bytes.NewReader(b), int64(len(b)))
	}
	archive, e := macArchive(bundledDesktopAsset)
	if e != nil {
		return "", e
	}
	return connectioninstall.InstallRelease(ctx, version, archive.Reader, archive.Size)
}
