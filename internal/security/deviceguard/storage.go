package deviceguard

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"suhang/usbnet/internal/security/securitypolicy"
)

type diskObservation struct {
	VolumeError bool                           `json:"volume_error"`
	ID          string                         `json:"id"`
	Model       string                         `json:"model"`
	Bytes       uint64                         `json:"bytes"`
	Volumes     []securitypolicy.StorageVolume `json:"volumes"`
}

// Associate only exact PnP IDs inside a verified USB subtree. An internal disk,
// a same-name disk or a volume with an unverified parent must never be attached.
func applyStorage(devices []securitypolicy.DeviceRecord, data []byte) error {
	var observations []diskObservation
	if len(data) > 65536 || json.Unmarshal(data, &observations) != nil || len(observations) > 128 {
		return fmt.Errorf("USB_STORAGE_METADATA_INVALID")
	}
	seen := map[string]bool{}
	for _, disk := range observations {
		id := strings.ToUpper(disk.ID)
		if id == "" || seen[id] || len(disk.Volumes) > 32 {
			return fmt.Errorf("USB_STORAGE_METADATA_INVALID")
		}
		seen[id] = true
		mounts := map[string]bool{}
		for _, v := range disk.Volumes {
			// Win32_LogicalDisk supplies a local drive letter; never execute or follow
			// a reported path, and never imply that null capacity means zero free space.
			if len(v.Mount) != 2 || v.Mount[0] < 'A' || v.Mount[0] > 'Z' || v.Mount[1] != ':' || mounts[v.Mount] || v.SpaceKnown && (v.Bytes == 0 || v.FreeBytes > v.Bytes) {
				return fmt.Errorf("USB_STORAGE_METADATA_INVALID")
			}
			mounts[v.Mount] = true
		}
	}
	for i := range devices {
		if !hasKind(devices[i], securitypolicy.KindStorage) {
			continue
		}
		ids := map[string]bool{}
		for _, id := range devices[i].NodeIDs {
			ids[strings.ToUpper(id)] = true
		}
		var disks []securitypolicy.StorageDisk
		for _, disk := range observations {
			if !ids[strings.ToUpper(disk.ID)] {
				continue
			}
			model := cleanName(disk.Model)
			if model == "USB 裝置" {
				model = ""
			}
			volumes := append([]securitypolicy.StorageVolume(nil), disk.Volumes...)
			for j := range volumes {
				name := cleanName(volumes[j].Name)
				if name == "USB 裝置" {
					name = ""
				}
				volumes[j].Name = name
			}
			sort.Slice(volumes, func(a, b int) bool { return volumes[a].Mount < volumes[b].Mount })
			problem := ""
			if disk.VolumeError {
				problem = "磁碟區資訊未完整讀取；可重新整理。"
			}
			disks = append(disks, securitypolicy.StorageDisk{Model: model, Bytes: disk.Bytes, Volumes: volumes, Problem: problem})
		}
		devices[i].Storage = disks
		if len(disks) == 0 {
			devices[i].StorageProblem = "Windows 未提供已關聯的磁碟資訊。"
			continue
		}
		if len(disks) == 1 && disks[0].Model != "" {
			devices[i].Name = disks[0].Model
		}
	}
	return nil
}
