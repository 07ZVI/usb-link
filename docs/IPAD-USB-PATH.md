# iPad USB network path

How USB Link turns an iPad's USB connection into an IP link to Windows. This page describes only what the current code does. Hardware acceptance is still pending ([validation](VALIDATION.md)).

## Path in one view

1. Windows enumerates the iPad as `USB\VID_05AC&PID_12AB` under a composite (`usbccgp`) parent.
2. A small vendor control request asks the iPad to switch to network mode (SET_MODE). The iPad re-enumerates in that mode.
3. Windows groups the NCM control interfaces into one CDC function, and the native `UsbNcm` driver creates a network adapter.
4. Fixed addresses: Windows `10.6.9.1`, Mac `10.6.9.2`, iPad `10.6.9.3` ([internet sharing](INTERNET-SHARING.md)).

## Control request

Code: `internal/app/ipadncm/check_windows.go`, `applecontrol_packet.go`.

- GET_MODE: `bmRequestType 0xC0`, `bRequest 0x45`, `wIndex 0`. The code requires the 4-byte reply `3,3,3,0` before it changes anything (`check_windows.go` around the `w.Control(0xc0, 0x45` call).
- SET_MODE: `bmRequestType 0xC0`, `bRequest 0x52`, `wIndex = mode`, one-byte reply. A reply of `0` is accepted; anything else is `MODE_ACK_NOT_ZERO` (`check_windows.go` around `w.Control(0xc0, 0x52`).
- `applecontrol_packet.go` admits only these two operations: 0x45 with index 0 and a 4-byte payload, and 0x52 with index 3 and a 1-byte payload.
- The direct path sends **mode 5** instead of 3 (`check_windows.go`, `requestedMode = 5`; `local_ncm_direct_packet.go`).
- Handle: `openControl` (`check_windows.go`) runs `CreateFile` then `WinUsb_Initialize` on the device path. The Apple-driver path uses `openAppleControl` (`applecontrol_windows.go`) instead. That path accepts only the `&MI_01` node, with service WinUSB, the expected Apple upper-filter stack, and a verified installed driver hash.
- After a successful SET_MODE, observation is limited to the same hub and physical port (`check_windows.go`, "Observe only the same hub and physical port").

## Configuration, grouping and driver binding

- `composite_settings_windows.go` reads `OriginalConfigurationValue` and `UsbccgpCapabilities` from the device's SetupAPI keys. It only reads them. Windows' usbccgp chooses the configuration.
- `grouping_config.go` admits the grouping trial only for an exact layout: configuration 5, two NCM control interfaces (2 and 4) whose slave links are interfaces 3 and 5, and no existing associations.
- `grouping_windows.go` writes `EnumeratorClass = 02 00 00` (`groupingBytes`) to the root's software key. Recovery deletes only a value that was originally absent.
- `grouping_existing_windows.go` checks that the root's `LowerFilters` contains `AppleLowerFilter`, that the driver is `486.0.0.0`, and that the grouping value is unchanged.
- `launcher/driver_windows.go` checks for `AppleLowerFilter` on the usbccgp node. If it is missing, the launcher asks for consent and installs the official Apple 486.0.0.0 driver after hashing every file. The launcher and grouping code only read `AppleLowerFilter`; no code path in those files removes it.
- Native network driver: `local_ncm_direct_network_windows.go` requires `Service = UsbNcm` and `INF = usbncm.inf` before it accepts the adapter (`network_windows.go` checks the same service).
- Addresses: `internal/platform/windows/netconfig/firewall_native_windows.go` sets per-peer rules for `10.6.9.1 ↔ 10.6.9.2` and `10.6.9.1 ↔ 10.6.9.3`.

## Obstacle, root cause, fix

| Obstacle | Root cause | How USB Link handles it | Code |
| --- | --- | --- | --- |
| iPad does not expose a network adapter by default | The NCM function is only enabled after the host asks for network mode | Read the mode, then send SET_MODE 0x52 with index 3 (or 5 on the direct path); accept only reply `0` | `check_windows.go`; `applecontrol_packet.go` |
| Two NCM control interfaces do not form one network function | Windows needs the two control interfaces grouped into one CDC function | Admit only the exact layout, then write `EnumeratorClass=020000` with a journal and restore | `grouping_config.go`; `grouping_windows.go`; `grouping_existing_windows.go` |
| Apple transport is unbound | `AppleLowerFilter` is absent from the device's lower filters | Consent-gated repair with the hash-checked official driver; nothing is removed | `launcher/driver_windows.go`; `grouping_existing_windows.go` |
| Photo access raises a Trust prompt | The MI_00 WPD photo interface is a prompt source | Start photo isolation, which disables the exact MI_00 DevNode with a journal and restore. Not fully verified on hardware | `default_network_isolation_windows.go`; `local_photo_native_windows.go`; `local_photo_journal.go` |
| Network adapter must bind to the right driver | Other drivers could claim the function | Accept only `UsbNcm` / `usbncm.inf` on one adapter | `local_ncm_direct_network_windows.go`; `network_windows.go` |
| Peers need predictable addresses and rules | Ad-hoc addresses are unreliable | Fixed `10.6.9.x` addresses with per-peer firewall rules | `firewall_native_windows.go`; `INTERNET-SHARING.md` |

## Known limits

- **iOS USB Restricted Mode**: when the iPad has been locked for more than an hour, iOS allows only charging until it is unlocked once after plugging in. This is iOS behavior; the codebase does not detect or handle it.
- **Windows Update**: the Apple driver is described as coming from Windows Update (`launcher/driver_windows.go`). The code re-checks `AppleLowerFilter` and offers repair when it is absent, but nothing in the repo shows that Windows Update re-attaches the filter.
- **Internet sharing**: Mac only. One authorized Mac can use it. Other USB peers, including the iPad, are never permitted by the Internet rules ([internet sharing](INTERNET-SHARING.md)).
- **Hardware acceptance**: pending for Windows, Mac and iPad ([validation](VALIDATION.md)).
- **Photo isolation**: the trust doc records that isolation was not fully verified and that a Trust click was still needed in at least one run ([IPAD-TRUST-PROMPTS.zh-CN.md](IPAD-TRUST-PROMPTS.zh-CN.md), around line 170).

## Prior art and credits

- Synacktiv, "iOS: a journey in the USB networking stack": https://www.synacktiv.com/en/publications/ios-a-journey-in-the-usb-networking-stack
- libimobiledevice/usbmuxd `src/usb.c`: https://github.com/libimobiledevice/usbmuxd/blob/master/src/usb.c and `USBMUXD_DEFAULT_DEVICE_MODE`. The repo's trust doc also cites usbmuxd's preflight source ([IPAD-TRUST-PROMPTS.zh-CN.md](IPAD-TRUST-PROMPTS.zh-CN.md)).
- Microsoft, usbccgp configuration selection: https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/selecting-the-configuration-for-a-multiple-interface--composite--usb-d
- Microsoft, interface collections: https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/support-for-interface-collections
- 0xbaksa/iphone-usb-reverse-tethering-windows, an independent Windows implementation for iPhone: https://github.com/0xbaksa/iphone-usb-reverse-tethering-windows
