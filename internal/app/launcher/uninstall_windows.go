//go:build windows && amd64

package launcher

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/platform/windows/interfaceconfig"
	"suhang/usbnet/internal/app/ipadncm"
	"suhang/usbnet/internal/app/macconnection"
	"suhang/usbnet/internal/platform/windows/netconfig"
	"suhang/usbnet/internal/app/usbhost"
	"time"
)

// The handle originates only from OpenGroupingRecoveryStore's share-zero file.
// Recheck its fixed machine location/type/identity; no RPC carries this handle.
func verifyUninstallRecoveryLease(dir string, lock windows.Handle) error {
	w, err := windows.GetWindowsDirectory()
	if err != nil || !strings.EqualFold(filepath.Clean(dir), filepath.Join(w, "Temp", "Suhang-iPad-Grouping-Recovery")) || lock == 0 {
		return errors.New("UNINSTALL_RECOVERY_LEASE_UNPROVEN")
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(lock, &info) != nil || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return errors.New("UNINSTALL_RECOVERY_LEASE_UNPROVEN")
	}
	var name [32768]uint16
	n, err := windows.GetFinalPathNameByHandle(lock, &name[0], uint32(len(name)), 0)
	if err != nil || n == 0 || n >= uint32(len(name)) || !strings.EqualFold(strings.TrimPrefix(windows.UTF16ToString(name[:n]), `\\?\`), filepath.Join(dir, "launch.lock")) {
		return errors.New("UNINSTALL_RECOVERY_LEASE_CHANGED")
	}
	return nil
}

// Restore-only work owns stopped SCM, the installed image, the machine-wide
// recovery file and global bridge runtime exclusion together. No created
// mapping is published as Ready and no signed archive is executed here.
func recoverUninstallInterfaces(parent context.Context, dir, system string, lock windows.Handle) (report macconnection.RecoveryReport, reboot bool, result error) {
	if err := verifyUninstallRecoveryLease(dir, lock); err != nil {
		return report, reboot, err
	}
	exe, err := os.Executable()
	if err != nil {
		return report, reboot, err
	}
	releaseSource, err := connectioninstall.PinCoreSelfSource(exe)
	if err != nil {
		return report, reboot, err
	}
	defer func() { result = errors.Join(result, releaseSource()) }()
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel() // synchronous factory calls are joined even past this deadline.
	reboot, result = connectioninstall.CompleteInstalledUninstall(ctx, exe, func(verifyCore func() error) error {
		var inner error
		report, inner = macconnection.WithExclusiveUninstallRecovery(dir, func(verifyDrain func() error) (restoreErr error) {
			verifyOwner := func() error {
				if err := verifyUninstallRecoveryLease(dir, lock); err != nil {
					return err
				}
				if err := verifyDrain(); err != nil {
					return err
				}
				return verifyCore()
			}
			if err := verifyOwner(); err != nil {
				return err
			}
			residentPlans, err := netconfig.PrepareResidentFirewallUninstall(ctx, dir, verifyOwner)
			if err != nil {
				return err
			}
			if err = netconfig.CompleteResidentPermissionBatch(ctx, "", residentPlans, func(c context.Context, script string) error {
				return netconfig.RunContext(c, script, log.New(os.Stderr, "USB uninstall: ", 0))
			}); err != nil {
				return err
			}
			if err := interfaceconfig.RequestPersistentUninstall(dir); err != nil {
				return err
			}
			if err := interfaceconfig.RequestOwnedDADUninstall(dir); err != nil {
				return err
			}
			if err := interfaceconfig.RestoreOwnedDADForUninstall(ctx, dir, func(id interfaceconfig.OwnedDADIdentity) error {
				if err := verifyOwner(); err != nil {
					return err
				}
				switch id.Scope.Role {
				case "host":
					return netconfig.VerifySharedHostRecreatedNative(id.Scope.Index, id.Scope.LUID, id.Instance)
				case "mac":
					return netconfig.VerifyOwnedMacRecreatedNative(id.Scope.Index, id.Scope.LUID, id.Instance)
				case "ipad":
					return ipadncm.VerifyOwnedIPadDADNative(ctx, id)
				}
				return errors.New("UNINSTALL_OWNED_DAD_ROLE_UNPROVEN")
			}); err != nil {
				return err
			}
			hostFactory, err := usbhost.HostUninstallFactoryRequired(dir)
			if err != nil {
				return err
			}
			macFactory, err := interfaceconfig.MacUninstallFactoryRequired(dir)
			if err != nil {
				return err
			}
			var dll string
			if hostFactory || macFactory {
				// Both names are compiled-in; no caller-selected version, path or DLL.
				archive, err := macArchive("assets/mac-payload-" + version + ".zip")
				if err != nil {
					return fmt.Errorf("UNINSTALL_BUILTIN_ARCHIVE_UNAVAILABLE: %w", err)
				}
				manifest, err := payload.ReadFile("assets/MAC-SOURCES-" + version + ".json")
				if err != nil {
					return fmt.Errorf("UNINSTALL_BUILTIN_MANIFEST_UNAVAILABLE: %w", err)
				}
				dll, err = macconnection.PrepareSharedHostDLLArchive(dir, archive, manifest)
				if err != nil {
					return fmt.Errorf("UNINSTALL_BUILTIN_DLL_UNPROVEN: %w", err)
				}
				pin, err := netconfig.PinVerifiedWintunNative(dll, log.New(os.Stderr, "USB uninstall: ", 0))
				if err != nil {
					return err
				}
				defer func() { restoreErr = errors.Join(restoreErr, pin.Close()) }()
			}
			if err := verifyOwner(); err != nil {
				return err
			}
			if err := ipadncm.RestorePersistentIPadForUninstall(ctx, dir); err != nil {
				return err
			}
			if err := verifyOwner(); err != nil {
				return err
			}
			if err := usbhost.RestoreOwnedHostForUninstall(ctx, dir, dll, verifyOwner); err != nil {
				return err
			}
			if err := interfaceconfig.RestoreOwnedMacForUninstall(ctx, dir, dll, verifyOwner); err != nil {
				return err
			}
			return verifyOwner()
		}, func() error {
			if err := verifyCore(); err != nil {
				return err
			}
			if err := verifyUninstallRecoveryLease(dir, lock); err != nil {
				return err
			}
			if err := usbhost.ConfirmHostUninstallComplete(dir); err != nil {
				return err
			}
			if err := interfaceconfig.ConfirmMacUninstallComplete(dir); err != nil {
				return err
			}
			absent, err := netconfig.MacAdapterAbsentNative()
			if err != nil || !absent {
				return errors.New("UNINSTALL_MAC_NATIVE_ABSENCE_UNPROVEN")
			}
			// Persistent originals have been verified before any operation that can
			// restart the root or destroy its UsbNcm mapping.
			if err := restoreUninstallIPadLegacy(ctx, dir, system, verifyCore); err != nil {
				return err
			}
			if err := verifyCore(); err != nil {
				return err
			}
			if err := usbhost.ConfirmHostUninstallComplete(dir); err != nil {
				return err
			}
			if err := interfaceconfig.ConfirmMacUninstallComplete(dir); err != nil {
				return err
			}
			if err := ipadncm.RestorePersistentIPadForUninstall(ctx, dir); err != nil {
				return err
			}
			absent, err = netconfig.MacAdapterAbsentNative()
			if err != nil || !absent {
				return errors.New("UNINSTALL_MAC_NATIVE_ABSENCE_UNPROVEN")
			}
			if err := verifyCore(); err != nil {
				return err
			}
			if err := interfaceconfig.FinishPersistentUninstall(dir); err != nil {
				return err
			}
			return interfaceconfig.ConfirmOwnedDADUninstallComplete(dir)
		})
		return inner
	})
	return report, reboot, result
}

func restoreUninstallIPadLegacy(ctx context.Context, dir, system string, verifyOwner func() error) error {
	if err := verifyOwner(); err != nil {
		return err
	}
	if err := ipadncm.RemoveApplicationFirewall(ctx); err != nil {
		return err
	}
	if err := verifyOwner(); err != nil {
		return err
	}
	if err := ipadncm.InitSimplifiedIPadNetwork(dir); err != nil {
		return err
	}
	if err := verifyOwner(); err != nil {
		return err
	}
	r := ipadncm.RecoverApplicationSession(dir, system)
	if r.Error != "" || r.Pending && !r.JournalCleared {
		return errors.New("UNINSTALL_IPAD_APPLICATION_RECOVERY_PENDING: " + r.Error)
	}
	if err := verifyOwner(); err != nil {
		return err
	}
	if problem := ipadncm.RestorePersistentNetworkGrouping(dir, system); problem != "" {
		return errors.New("UNINSTALL_IPAD_GROUPING_RESTORE_PENDING: " + problem)
	}
	if err := verifyOwner(); err != nil {
		return err
	}
	if err := ipadncm.RecoverIPadSoftwareReconnect(dir); err != nil {
		return err
	}
	return verifyOwner()
}
