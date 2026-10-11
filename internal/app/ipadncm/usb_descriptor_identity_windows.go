//go:build windows && amd64

package ipadncm

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"suhang/usbnet/internal/transport/ipadsession"
	"unsafe"

	"golang.org/x/sys/windows"
)

func readUSBDescriptorIdentity(ctx context.Context, h windows.Handle, d *Device, dd []byte) {
	d.USBProductReadStatus, d.USBSerialReadStatus = "USB_PRODUCT_INDEX_MISSING", "USB_SERIAL_INDEX_MISSING"
	d.USBSerialIndex = dd[16]
	if dd[15] == 0 || dd[16] == 0 {
		d.Errors = append(d.Errors, "USB_IDENTITY_DESCRIPTOR_INDEX_MISSING")
		return
	}
	langs, err := descriptor(ctx, h, d.port, 3, 0, 255)
	if err != nil {
		d.USBProductReadStatus, d.USBSerialReadStatus = "USB_LANGID_READ_"+eno(err), "USB_LANGID_READ_"+eno(err)
		d.Errors = append(d.Errors, "USB_IDENTITY_LANGID_READ_FAILED")
		return
	}
	lang, status := usbIdentityLanguage(langs)
	if lang == 0 {
		d.USBProductReadStatus, d.USBSerialReadStatus = status, status
		d.Errors = append(d.Errors, status)
		return
	}
	d.USBIdentityLanguage = lang
	read := func(index byte, serial bool) (string, string, *USBIdentityStringFailureShape, int) {
		b, err := descriptorLanguage(ctx, h, d.port, 3, index, lang, 255)
		if err != nil {
			return "", "USB_STRING_READ_" + eno(err), nil, 0
		}
		if serial {
			return parseUSBSerialDescriptor(b, d.pid)
		}
		value, status, shape := parseUSBIdentityStringWithFailureShape(b)
		return value, status, shape, 0
	}
	d.USBProduct, d.USBProductReadStatus, _, _ = read(dd[15], false)
	d.usbSerial, d.USBSerialReadStatus, d.USBSerialFailureShape, d.USBSerialPaddingNULUnits = read(dd[16], true)
	d.USBSerialSHA256 = ipadsession.USBDescriptorSerialDigest(d.usbSerial)
	if !ipadsession.ValidUSBDescriptorIdentity(d.usbSerial, d.USBProduct) {
		d.Errors = append(d.Errors, "USB_SERIAL_OR_PRODUCT_DESCRIPTOR_UNCONFIRMED")
		return
	}
	// A completed string request is not proof the same connection remained
	// present while the hub was queried. Re-read cached device/port information.
	info := make([]byte, 4096)
	binary.LittleEndian.PutUint32(info, d.port)
	n, err := ioctl(ctx, h, 0x220448, info)
	if err != nil || n < 35 || binary.LittleEndian.Uint32(info[31:]) != 1 || !bytes.Equal(info[4:22], dd) || info[22] != d.CurrentConfiguration {
		d.Errors = append(d.Errors, "USB_CONNECTION_CHANGED_DURING_DESCRIPTOR_READ")
		return
	}
	d.usbIdentityPortStable = true
}

// Bind a fresh descriptor to its precise PRESENT physical root, not merely to
// the count of Apple devices. CM and hub interface paths are independently read.
func verifyUSBDescriptorRoot(ctx context.Context, d *Device, nodes []Node) {
	if !d.usbIdentityPortStable || !ipadsession.ValidUSBDescriptorIdentity(d.usbSerial, d.USBProduct) {
		return
	}
	var root *Node
	for i := range nodes {
		if nodes[i].IDPrefix == `USB\VID_05AC&PID_12AB` {
			if root != nil {
				d.Errors = append(d.Errors, "USB_DESCRIPTOR_ROOT_NOT_UNIQUE")
				return
			}
			root = &nodes[i]
		}
	}
	if root == nil || root.devInst == 0 || !usbDescriptorRootMatches(root.instanceID, d.usbSerial) {
		d.Errors = append(d.Errors, "USB_DESCRIPTOR_NATIVE_SERIAL_MISMATCH_OR_ROOT_ABSENT")
		return
	}
	p, err := windows.UTF16PtrFromString(root.instanceID)
	var located windows.DEVINST
	if err != nil || ctx.Err() != nil {
		d.Errors = append(d.Errors, "USB_DESCRIPTOR_NATIVE_ROOT_UNREADABLE")
		return
	}
	cr, _, _ := portableCfg.NewProc("CM_Locate_DevNodeW").Call(uintptr(unsafe.Pointer(&located)), uintptr(unsafe.Pointer(p)), 0)
	var id [1024]uint16
	idCR, _, _ := portableID.Call(uintptr(root.devInst), uintptr(unsafe.Pointer(&id[0])), uintptr(len(id)), 0)
	parent, parentCR := softwareParentID(root.devInst)
	hub, hubCR := softwareHubInstance(ctx, d.hub)
	if cr != 0 || located != root.devInst || idCR != 0 || !strings.EqualFold(windows.UTF16ToString(id[:]), root.instanceID) || parentCR != 0 || hubCR != 0 || parent == "" || hub == "" || !strings.EqualFold(parent, hub) {
		d.Errors = append(d.Errors, "USB_DESCRIPTOR_EXACT_NATIVE_HUB_BINDING_FAILED")
		return
	}
	d.USBDescriptorIdentityVerified = true
}

func descriptorAttachment(s Snapshot) usbDescriptorAttachment {
	if !networkOnlyUSBEligible(s) {
		return usbDescriptorAttachment{}
	}
	d := s.Devices[0]
	return usbDescriptorAttachment{root: exactIPadRoot(s), hub: d.hub, port: d.port, serial: d.usbSerial, product: d.USBProduct, verified: d.USBDescriptorIdentityVerified}
}
