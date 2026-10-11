// Package devicecheck performs read-only USB role inventory. A USB-C connector,
// charging capability or installed UFX file is not proof of a usable data link.
package devicecheck

const Script = `$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);
$computer=Get-CimInstance Win32_ComputerSystem;
$boards=@(Get-CimInstance Win32_BaseBoard | Select-Object Manufacturer,Product,Version);
$os=Get-CimInstance Win32_OperatingSystem;
$controllers=@(Get-CimInstance Win32_USBController | ForEach-Object {
  [ordered]@{Name=$_.Name;Manufacturer=$_.Manufacturer;Problem=$_.ConfigManagerErrorCode;DeviceID=($_.PNPDeviceID -split '\\',3 | Select-Object -First 2) -join '\'}
});
$devices=@(Get-CimInstance Win32_PnPEntity | Where-Object { $_.PNPClass -in @('USB','USBDevice') -or $_.Service -match '^(Ufx|Urs|GenericUSBFn|UsbFn)' } | Select-Object -First 256 | ForEach-Object {
  [ordered]@{Name=$_.Name; Class=$_.PNPClass; Service=$_.Service; Problem=$_.ConfigManagerErrorCode; HardwareID=@($_.HardwareID); DeviceID=($_.PNPDeviceID -split '\\',3 | Select-Object -First 2) -join '\'}
});
$functionDrivers=@(Get-CimInstance Win32_SystemDriver | Where-Object {$_.Name -match '^(Ufx|Urs|GenericUSBFn|UsbFn)'} | Select-Object Name,State,StartMode);
[ordered]@{Protocol='SUHANG-USB-DEVICE-CHECK/2';Manufacturer=$computer.Manufacturer;Model=$computer.Model;BaseBoards=$boards;Windows=$os.Caption;Version=$os.Version;Build=$os.BuildNumber;Architecture=$os.OSArchitecture;USBControllers=$controllers;Devices=$devices;FunctionDrivers=$functionDrivers;Result='INVENTORY_ONLY_NOT_CONNECTION_PROOF';Scope='Read-only; no binding, network, boot, firewall or security changes'} | ConvertTo-Json -Depth 8 -Compress`
