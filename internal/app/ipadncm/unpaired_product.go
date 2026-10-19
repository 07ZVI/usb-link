package ipadncm

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"suhang/usbnet/internal/transport/ipadsession"
	"sync/atomic"
)

// The private owner is persistent USB consent, not an Apple pairing identity.
// It binds one exact root and descriptor digest. A different device requires
// OFF plus verified restoration before a new owner can be enrolled.
type unpairedProductOwner struct {
	Version int    `json:"version"`
	Root    string `json:"device_root"`
	Digest  string `json:"usb_descriptor_sha256"`
}

func (o unpairedProductOwner) valid() bool {
	b, e := hex.DecodeString(o.Digest)
	return o.Version == 1 && ipadsession.USBGrant(o.Root, "12AB", "network-only-scope").Valid() && e == nil && len(b) == 32 && o.Digest == strings.ToLower(o.Digest)
}
func (o unpairedProductOwner) matches(root, digest string) bool {
	return o.valid() && strings.EqualFold(o.Root, root) && o.Digest == digest
}
func decodeUnpairedProductOwner(b []byte) (unpairedProductOwner, error) {
	var o unpairedProductOwner
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var tail any
	if d.Decode(&o) != nil || d.Decode(&tail) != io.EOF || !o.valid() {
		return o, fmt.Errorf("UNPAIRED_PRODUCT_OWNER_INVALID")
	}
	return o, nil
}

func decodeUnpairedProductChoice(b []byte) (bool, error) {
	var p struct {
		Version int   `json:"version"`
		Enabled *bool `json:"enabled"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var tail any
	if d.Decode(&p) != nil || p.Version != 1 || p.Enabled == nil || d.Decode(&tail) != io.EOF {
		return false, fmt.Errorf("UNPAIRED_PRODUCT_CHOICE_INVALID")
	}
	return *p.Enabled, nil
}

var unpairedProductConfigured atomic.Bool

func validUnpairedReceiptSchema(version int, persistent bool) bool {
	return version == 1 && !persistent || version == 2 && persistent
}

// Configuration alone supplies no device authority or U1 features.
func UnpairedNetworkOnlyProductConfigured() bool { return unpairedProductConfigured.Load() }

type unpairedProductDriverProof struct {
	configured, enabled, consentBound, ownerExact, storeProtected  bool
	official, native, hash, receipt, receiptRoots, serviceReadable bool
	originalState, originalStart, state, start                     uint32
}

func (p unpairedProductDriverProof) valid() bool {
	return p.configured && p.enabled && p.consentBound && p.ownerExact && p.storeProtected && p.official && p.native && p.hash && p.receipt && p.receiptRoots && p.serviceReadable &&
		(p.originalState == 1 || p.originalState == 4) && (p.originalStart == 2 || p.originalStart == 3) && p.state == 1 && p.start == 3
}

// Decide startup recovery without mutating an existing owner. Unknown owner,
// receipt or choice is an error; it must never select the restore branch.
func unpairedProductPreserve(choiceOn, ownerExists, ownerValid, receiptExists, receiptValid, rootsMatch bool) (bool, error) {
	if !choiceOn {
		return false, nil
	} // Explicit OFF retains original-value recovery.
	if ownerExists && (!ownerValid || !receiptExists || !receiptValid || !rootsMatch) {
		return false, fmt.Errorf("UNPAIRED_PRODUCT_PERSISTENT_OWNER_UNPROVEN")
	}
	return choiceOn && ownerExists, nil
}

// Enrollment must finish dependencies before any protected policy mutation.
// The main caller has already acquired actual USB consent.
func runUnpairedProductPreparation(dependencies func() (bool, string), prepare func() string, bind func() string) string {
	ready, problem := dependencies()
	if problem != "" {
		return problem
	}
	if !ready {
		if problem = prepare(); problem != "" {
			return problem
		}
		ready, problem = dependencies()
		if problem != "" {
			return problem
		}
		if !ready {
			return "UNPAIRED_PRODUCT_DEPENDENCIES_UNPROVEN"
		}
	}
	return bind()
}

func runUnpairedProductEnrollment(persistOn, capture, owner, apply func() error) error {
	for _, step := range []func() error{persistOn, capture, owner, apply} {
		if e := step(); e != nil {
			return e
		}
	}
	return nil
}

func runUnpairedProductOff(persistOff, restoreOriginals, clearOwner func() error) error {
	for _, step := range []func() error{persistOff, restoreOriginals, clearOwner} {
		if e := step(); e != nil {
			return e
		}
	}
	return nil
}

func UnpairedProductDriverNotice(problem string) string {
	if strings.Contains(problem, "DRIVER_HASH_NOT_EXPECTED") {
		return "蘋果 USB 驅動版本與本程式驗證版本不同，已暫停 iPad 接入並保留目前系統設定。請安裝本程式支援的官方 USB 驅動，再重新開啟程式；不會自動修改驅動或開啟信任。"
	}
	if strings.Contains(problem, "DRIVER_VERSION_CHECK") {
		return "無法核對蘋果 USB 驅動檔案，已暫停 iPad 接入；請檢查官方元件安裝或權限，目前系統設定保留。"
	}
	return ""
}

// Saved product policy only controls retention of an existing exact obligation;
// it never supplies live device/network authority. Unknown proof cannot restore.
func runProductStartupGrouping(preserve bool, prove func() (bool, error), restore func() error) (bool, error) {
	if !preserve {
		return false, restore()
	}
	found, e := prove()
	if e != nil {
		return false, e
	}
	return found, nil
}
