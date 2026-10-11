package netconfig

import (
	"fmt"
	"suhang/usbnet/internal/transport/usbaddress"
)

// Read-only, startup-only driver proof before recovering a journaled host
// address. The later adapter removal performs its own fresh driver check.
func SharedHostIdentityReadback(index uint32) (string, error) {
	if index == 0 {
		return "", fmt.Errorf("USB_HOST_MAPPING_UNPROVEN")
	}
	return fmt.Sprintf(`$ErrorActionPreference='Stop';
$a=@(Get-NetAdapter -IncludeHidden | Where-Object {[guid]$_.InterfaceGuid -eq [guid]'%s' -or $_.Name -ceq 'USB Link Host'});
if($a.Count -ne 1 -or [guid]$a[0].InterfaceGuid -ne [guid]'%s' -or $a[0].Name -cne 'USB Link Host' -or [uint32]$a[0].ifIndex -ne %d){throw 'USB_HOST_DRIVER_MAPPING_UNPROVEN'};
$id=[string]$a[0].PnPDeviceID;
if([string]::IsNullOrWhiteSpace($id) -or $id.Contains('*') -or $id.Contains('?')){throw 'USB_HOST_DRIVER_INSTANCE_UNPROVEN'};
$p=@(Get-CimInstance -ClassName Win32_PnPEntity | Where-Object {$_.DeviceID -ieq $id});
if($p.Count -ne 1 -or $p[0].Service -ine 'Wintun' -or [string]$p[0].ClassGuid -ine '{4d36e972-e325-11ce-bfc1-08002be10318}'){throw 'USB_HOST_DRIVER_IDENTITY_UNPROVEN'};
Write-Output 'USB_HOST_DRIVER_IDENTITY_VERIFIED';`, usbaddress.HostGUID, usbaddress.HostGUID, index), nil
}
