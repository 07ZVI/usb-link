//go:build windows && amd64

package ipadncm

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"howett.net/plist"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var appleSerialPattern = regexp.MustCompile(`^[a-fA-F0-9-]{20,40}$`)

func exactIPadRoot(s Snapshot) string {
	var root string
	for _, n := range s.Nodes {
		if n.IDPrefix == `USB\VID_05AC&PID_12AB` && n.instanceID != "" {
			if root != "" {
				return ""
			}
			root = n.instanceID
		}
	}
	if len(s.Devices) != 1 || s.Devices[0].PID != "12AB" {
		return ""
	}
	return root
}
func muxDial(ctx context.Context) (net.Conn, error) {
	c, e := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", "127.0.0.1:27015")
	if e == nil {
		c.SetDeadline(queryDeadline(ctx, 3*time.Second))
	}
	return c, e
}
func usbMuxTarget(ctx context.Context, expected string) (uint64, string, error) {
	c, e := muxDial(ctx)
	if e != nil {
		return 0, "", e
	}
	defer c.Close()
	if sendMux(c, muxMessage("ListDevices")) != nil {
		return 0, "", fmt.Errorf("list send")
	}
	m, e := receiveMux(c, false)
	var list []any
	listSupported := false
	if v, ok := m["DeviceList"].([]any); e == nil && ok {
		listSupported = true
		if len(v) > 64 {
			return 0, "", fmt.Errorf("list limit")
		}
		list = v
	}
	if !listSupported || len(list) == 0 {
		c.Close()
		c, e = muxDial(ctx)
		if e != nil {
			return 0, "", e
		}
		defer c.Close()
		if sendMux(c, muxMessage("Listen")) != nil {
			return 0, "", fmt.Errorf("listen send")
		}
		m, e = receiveMux(c, false)
		if e != nil || m["Number"] != uint64(0) {
			return 0, "", fmt.Errorf("listen rejected")
		}
		window := 2 * time.Second
		if listSupported {
			window = emptyMuxListWait
		}
		c.SetDeadline(queryDeadline(ctx, window))
		devices := map[uint64]map[string]any{}
		for i := 0; i < 64; i++ {
			m, e = receiveMux(c, true)
			if e != nil {
				if ne, ok := e.(net.Error); ok && ne.Timeout() {
					break
				}
				return 0, "", fmt.Errorf("listen failed")
			}
			if m["MessageType"] == "Attached" {
				p, ok := m["Properties"].(map[string]any)
				if !ok {
					return 0, "", fmt.Errorf("missing properties")
				}
				id, _ := p["DeviceID"].(uint64)
				if id == 0 {
					id, _ = m["DeviceID"].(uint64)
				}
				devices[id] = m
			}
			if m["MessageType"] == "Detached" {
				id, _ := m["DeviceID"].(uint64)
				delete(devices, id)
			}
			if i == 63 {
				return 0, "", fmt.Errorf("event limit")
			}
		}
		for _, v := range devices {
			list = append(list, v)
		}
	}
	var found uint64
	var serial string
	usbCount := 0
	for _, v := range list {
		m, ok := v.(map[string]any)
		if !ok {
			return 0, "", fmt.Errorf("bad entry")
		}
		p, ok := m["Properties"].(map[string]any)
		if !ok {
			return 0, "", fmt.Errorf("bad properties")
		}
		if p["ConnectionType"] != "USB" {
			continue
		}
		usbCount++
		s, _ := p["SerialNumber"].(string)
		id, _ := p["DeviceID"].(uint64)
		if id == 0 {
			id, _ = m["DeviceID"].(uint64)
		}
		if appleSerialPattern.MatchString(s) && canonicalSerial(s) == canonicalSerial(expected) {
			found, serial = id, s
		}
	}
	if usbCount != 1 || found == 0 || serial == "" {
		if usbCount != 1 {
			return 0, "", fmt.Errorf("PAIRED_MUX_USB_TARGET_ABSENT_OR_AMBIGUOUS")
		}
		return 0, "", fmt.Errorf("PAIRED_MUX_PHYSICAL_SERIAL_NOT_MATCHED")
	}
	return found, serial, nil
}
func muxPairRecord(ctx context.Context, serial string) []byte {
	c, e := muxDial(ctx)
	if e != nil {
		return nil
	}
	defer c.Close()
	m := muxMessage("ReadPairRecord")
	m["PairRecordID"] = serial
	if sendMux(c, m) != nil {
		return nil
	}
	r, e := receiveMux(c, false)
	if e != nil {
		return nil
	}
	b, _ := r["PairRecordData"].([]byte)
	return b
}
func appleLocalPairRecord(serial string) []byte {
	if !appleSerialPattern.MatchString(serial) {
		return nil
	}
	return appleLocalCredentialFile(serial + ".plist")
}
func appleLocalCredentialFile(leaf string) []byte {
	if filepath.Base(leaf) != leaf {
		return nil
	}
	base, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return nil
	}

	path := base
	for _, part := range []string{"Apple", "Lockdown", leaf} {
		path = filepath.Join(path, part)
		p, _ := windows.UTF16PtrFromString(path)
		a, e := windows.GetFileAttributes(p)
		if e != nil || a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return nil
		}
	}
	f, e := os.Open(path)
	if e != nil {
		return nil
	}
	defer f.Close()
	stat, e := f.Stat()
	if e != nil || !stat.Mode().IsRegular() || stat.Size() <= 0 || stat.Size() > 512*1024 {
		return nil
	}
	b, e := io.ReadAll(io.LimitReader(f, 512*1024+1))
	if e != nil || len(b) > 512*1024 {
		return nil
	}
	return b
}
func AuthenticateCurrentUSB() PairedIdentity {
	out := PairedIdentity{Error: "PAIRED_PHYSICAL_USB_ROOT_UNAVAILABLE"}
	before := Inspect()
	root := exactIPadRoot(before)
	if root == "" {
		return out
	}
	parts := strings.Split(root, `\`)
	serial := parts[len(parts)-1]
	if !appleSerialPattern.MatchString(serial) {
		out.Error = "PAIRED_PHYSICAL_ROOT_SERIAL_UNAVAILABLE"
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	id, muxSerial, e := usbMuxTarget(ctx, serial)
	if e != nil {
		out.Error = "PAIRED_USB_TRANSPORT_QUERY_FAILED"
		// Only fixed local classifications are exported, never daemon data,
		// instance IDs, credentials or arbitrary native/network error strings.
		switch e.Error() {
		case "PAIRED_MUX_USB_TARGET_ABSENT_OR_AMBIGUOUS", "PAIRED_MUX_PHYSICAL_SERIAL_NOT_MATCHED":
			out.Error = e.Error()
		}
		return out
	}
	record := muxPairRecord(ctx, muxSerial)
	if len(record) == 0 {
		record = appleLocalPairRecord(muxSerial)
	}
	// Some official records omit SystemBUID. Read the daemon's existing
	// BUID; never create a replacement trust record or modify Apple settings.
	var pair map[string]any
	if len(record) <= 512*1024 {
		if _, e := plist.Unmarshal(record, &pair); e == nil {
			buid, _ := pair["SystemBUID"].(string)
			if buid == "" {
				if c, e := muxDial(ctx); e == nil {
					if sendMux(c, muxMessage("ReadBUID")) == nil {
						if reply, e := receiveMux(c, false); e == nil {
							buid, _ = reply["BUID"].(string)
						}
					}
					c.Close()
				}
				if buid == "" {
					var system map[string]any
					if b := appleLocalCredentialFile("SystemConfiguration.plist"); len(b) > 0 {
						if _, e := plist.Unmarshal(b, &system); e == nil {
							buid, _ = system["SystemBUID"].(string)
						}
					}
				}
				if buid != "" && len(buid) <= 128 {
					pair["SystemBUID"] = buid
					record, _ = plist.Marshal(pair, plist.XMLFormat)
				}
			}
		}
	}
	out = authenticatePair(ctx, muxSerial, record, func(ctx context.Context) (net.Conn, error) {
		c, e := muxDial(ctx)
		if e != nil {
			return nil, e
		}
		m := muxMessage("Connect")
		m["DeviceID"] = id
		m["PortNumber"] = uint64(0x7ef2)
		if sendMux(c, m) != nil {
			c.Close()
			return nil, fmt.Errorf("connect write")
		}
		r, e := receiveMux(c, false)
		if e != nil || r["Number"] != uint64(0) {
			c.Close()
			return nil, fmt.Errorf("connect failed")
		}
		return c, nil
	})
	if out.Authenticated {
		after := Inspect()
		if exactIPadRoot(after) != root || !sameUSBTarget(before, after) {
			return PairedIdentity{Error: "PAIRED_DEVICE_CHANGED_DURING_AUTHENTICATION"}
		}
	}
	return out
}
