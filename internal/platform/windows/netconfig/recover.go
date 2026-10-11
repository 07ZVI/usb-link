package netconfig

import "fmt"
import "strings"
import "suhang/usbnet/internal/transport/usbaddress"

// RecoverAdapter is used only with a validated protected journal and while the
// exclusive USB bridge runtime lock is held. Never removes a driver package.
func RecoverAdapter(guid, token string) (string, error) {
	if _, err := VerifyCleanup(guid, token); err != nil {
		return "", err
	}
	script := fmt.Sprintf(`$ErrorActionPreference='Stop';
$a=@(Get-NetAdapter -IncludeHidden | Where-Object {[guid]$_.InterfaceGuid -eq [guid]'%s'});
if($a.Count -gt 1){throw 'Ambiguous owned adapter'};
if($a.Count -eq 1){
 if($a[0].Name -cne 'Suhang USB' -and $a[0].Name -cne 'USB Link'){throw 'Owned adapter name changed'};
 $id=[string]$a[0].PnPDeviceID;
 if([string]::IsNullOrWhiteSpace($id) -or $id.Contains('*') -or $id.Contains('?')){throw 'Owned adapter instance unavailable'};
 $p=@(Get-CimInstance -ClassName Win32_PnPEntity | Where-Object {$_.DeviceID -ieq $id});
 if($p.Count -ne 1 -or $p[0].Service -ine 'Wintun' -or [string]$p[0].ClassGuid -ine '{4d36e972-e325-11ce-bfc1-08002be10318}'){throw 'Owned adapter driver identity mismatch'};
 Write-Output ('Removing owned stale Wintun adapter: '+$id);
 & "$env:SystemRoot\System32\pnputil.exe" /remove-device $id;
 if($LASTEXITCODE -ne 0){throw ('Owned adapter removal exit='+$LASTEXITCODE)};
 $deadline=(Get-Date).AddSeconds(10);
 do {$remaining=@(Get-NetAdapter -IncludeHidden | Where-Object {[guid]$_.InterfaceGuid -eq [guid]'%s'});if($remaining.Count -eq 0){break};Start-Sleep -Milliseconds 200}while((Get-Date) -lt $deadline);
 if($remaining.Count -ne 0){throw 'Owned adapter remains after removal'}
}; Write-Output 'OWNED_ADAPTER_RECOVERY_FINISHED';`, guid, guid)
	if strings.EqualFold(guid, usbaddress.HostGUID) {
		script = strings.Replace(script, "if($a[0].Name -cne 'Suhang USB' -and $a[0].Name -cne 'USB Link')", "if($a[0].Name -cne 'USB Link Host')", 1)
		// Exact owned IPv4 removal must have finished before deleting the host
		// adapter. A newly added foreign address keeps the adapter and journal.
		script = strings.Replace(script, "Write-Output ('Removing owned stale Wintun adapter: '+$id);", "if(@(Get-NetIPAddress -ErrorAction Stop | Where-Object {$_.AddressFamily -eq 'IPv4' -and $_.InterfaceIndex -eq $a[0].ifIndex}).Count -ne 0){throw 'USB_HOST_IPV4_REMAINS_BEFORE_ADAPTER_REMOVAL'};\n Write-Output ('Removing owned stale Wintun adapter: '+$id);", 1)
	}
	return script, nil
}

// FullRecovery keeps cleanup, adapter ownership checks and final verification
// in one PowerShell process without weakening any of their postconditions.
func FullRecovery(guid, token string) (string, error) {
	_, cleanup, e := Scripts(1, guid, 1500, token)
	if e != nil {
		return "", e
	}
	files, e := FileReceiverRule(guid, token, false)
	if e != nil {
		return "", e
	}
	adapter, e := RecoverAdapter(guid, token)
	if e != nil {
		return "", e
	}
	verify, e := VerifyCleanup(guid, token)
	if e != nil {
		return "", e
	}
	return files + cleanup + adapter + verify, nil
}
