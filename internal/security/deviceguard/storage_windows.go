//go:build windows && amd64

package deviceguard

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
	"syscall"
	"time"
	"unicode/utf16"
)

// Read-only Windows CIM associations cover both USBSTOR and SCSI/UAS disks.
// The script is fixed; exact local IDs are passed as data, never query/code.
// No serial numbers or unrelated disk/volume data are returned to the UI.
const storageScript = `
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$ids=Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $env:USB_LINK_STORAGE_IDS
$wanted=@{}; foreach($id in $ids){$wanted[$id.ToUpperInvariant()]=$true}
$result=@(foreach($disk in CimCmdlets\Get-CimInstance -ClassName Win32_DiskDrive -OperationTimeoutSec 3){
 if(!$disk.PNPDeviceID -or !$wanted.ContainsKey($disk.PNPDeviceID.ToUpperInvariant())){continue}
 $volumes=@{}; $volumeRows=@(); $volumeProblem=$false
 try {
  foreach($partition in CimCmdlets\Get-CimAssociatedInstance -InputObject $disk -Association Win32_DiskDriveToDiskPartition -ResultClassName Win32_DiskPartition -OperationTimeoutSec 3){
   foreach($volume in CimCmdlets\Get-CimAssociatedInstance -InputObject $partition -Association Win32_LogicalDiskToPartition -ResultClassName Win32_LogicalDisk -OperationTimeoutSec 3){
    if($volume.DeviceID -notmatch '^[A-Z]:$' -or $volumes.ContainsKey($volume.DeviceID)){continue}
    $volumes[$volume.DeviceID]=$true
    $known=$null -ne $volume.Size -and $null -ne $volume.FreeSpace -and $volume.Size -gt 0
    $volumeRows+=@{name=[string]$volume.VolumeName;mount=[string]$volume.DeviceID;bytes=[uint64]$volume.Size;free_bytes=[uint64]$volume.FreeSpace;space_known=[bool]$known}
   }
  }
 } catch { $volumeProblem=$true }
 @{id=[string]$disk.PNPDeviceID;model=[string]$disk.Model;bytes=[uint64]$disk.Size;volumes=@($volumeRows);volume_error=[bool]$volumeProblem}
})
Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject @($result) -Depth 5 -Compress
`

type storageOutput struct {
	data     []byte
	overflow bool
}

func (b *storageOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 65536 - len(b.data)
	if n > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	b.data = append(b.data, p...)
	return n, nil
}

// Optional display metadata never delays admission checks or empties the USB
// list on failure. A hung Windows provider is killed after eight seconds.
func EnrichStorage(parent context.Context, devices []securitypolicy.DeviceRecord) {
	ids := []string{}
	seen := map[string]bool{}
	for _, d := range devices {
		if hasKind(d, securitypolicy.KindStorage) {
			for _, id := range d.NodeIDs {
				if !seen[id] {
					seen[id] = true
					ids = append(ids, id)
				}
			}
		}
	}
	if len(ids) == 0 {
		return
	}
	problem := "Windows 儲存資訊無法讀取；可重新整理。"
	defer func() {
		for i := range devices {
			if hasKind(devices[i], securitypolicy.KindStorage) && len(devices[i].Storage) == 0 && devices[i].StorageProblem == "" {
				devices[i].StorageProblem = problem
			}
		}
	}()
	raw, e := json.Marshal(ids)
	if e != nil || len(raw) > 20000 {
		return
	}
	system, e := windows.GetSystemDirectory()
	if e != nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	words := utf16.Encode([]rune(storageScript))
	encoded := make([]byte, 2*len(words))
	for i, w := range words {
		binary.LittleEndian.PutUint16(encoded[i*2:], w)
	}
	cmd := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	cmd.WaitDelay = time.Second
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(key, "PSModulePath") && !strings.EqualFold(key, "USB_LINK_STORAGE_IDS") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "PSModulePath="+filepath.Join(system, "WindowsPowerShell", "v1.0", "Modules"), "USB_LINK_STORAGE_IDS="+string(raw))
	var output, errors storageOutput
	cmd.Stdout = &output
	cmd.Stderr = &errors
	if cmd.Run() != nil {
		if ctx.Err() != nil {
			problem = "儲存資訊讀取逾時或已取消；可重新整理。"
		}
		return
	}
	if output.overflow || applyStorage(devices, output.data) != nil {
		return
	}
}
