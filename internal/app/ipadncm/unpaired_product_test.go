package ipadncm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestUnpairedProductV2CannotBeRestoredByLegacyV1Reader(t *testing.T) {
	for _, c := range []struct {
		version       int
		marker, valid bool
	}{{1, false, true}, {2, true, true}, {1, true, false}, {2, false, false}, {3, true, false}} {
		if validUnpairedReceiptSchema(c.version, c.marker) != c.valid {
			t.Fatal(c)
		}
	}
	// This is the old published receipt shape and strict decoder, rather than
	// accepting a marker as device authority in the new product.
	var old struct {
		Version int    `json:"version"`
		State   uint32 `json:"original_amds_state"`
		Start   uint32 `json:"original_amds_start_type"`
	}
	d := json.NewDecoder(bytes.NewReader([]byte(`{"version":2,"original_amds_state":4,"original_amds_start_type":2,"persistent_usb_owner":true}`)))
	d.DisallowUnknownFields()
	if d.Decode(&old) == nil {
		t.Fatal("legacy .84 decoder accepts protected product receipt")
	}
}

func testUnpairedProductOwner() unpairedProductOwner {
	return unpairedProductOwner{1, `USB\VID_05AC&PID_12AB\EXACT123456789`, strings.Repeat("a", 64)}
}

func TestUnpairedProductOwnerExactScopeAndStrictEncoding(t *testing.T) {
	o := testUnpairedProductOwner()
	b, _ := json.Marshal(o)
	got, e := decodeUnpairedProductOwner(b)
	if e != nil || got != o || !o.matches(strings.ToLower(o.Root), o.Digest) {
		t.Fatal(got, e)
	}
	if o.matches(o.Root+"OTHER", o.Digest) || o.matches(o.Root, strings.Repeat("b", 64)) {
		t.Fatal("owner changed target")
	}
	for _, data := range [][]byte{append(append([]byte(nil), b...), []byte(" {}")...), []byte(`{"version":1,"device_root":"USB\\VID_05AC&PID_12AB\\EXACT","usb_descriptor_sha256":"aa","pair_identity":"x"}`)} {
		if _, e := decodeUnpairedProductOwner(data); e == nil {
			t.Fatal("invalid owner accepted")
		}
	}
}

func TestUnpairedProductRestartPreservesOwnedOriginalsOnly(t *testing.T) {
	for _, c := range []struct {
		name                                           string
		on, owner, valid, receipt, receiptValid, roots bool
		preserve, fail                                 bool
	}{
		{"new desired ON no authority", true, false, false, false, false, false, false, false},
		{"restart upgrade owned originals", true, true, true, true, true, true, true, false},
		{"corrupt owner", true, true, false, true, true, true, false, true},
		{"owner missing original receipt", true, true, true, false, false, false, false, true},
		{"wrong node root", true, true, true, true, true, false, false, true},
		{"explicit OFF restores recorded originals", false, true, true, true, true, true, false, false},
		{"OFF partial owner can recover", false, true, true, false, false, false, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			p, e := unpairedProductPreserve(c.on, c.owner, c.valid, c.receipt, c.receiptValid, c.roots)
			if p != c.preserve || (e != nil) != c.fail {
				t.Fatal(p, e)
			}
		})
	}
}

func TestUnpairedProductDependencyConsentPrecedesProtection(t *testing.T) {
	for _, c := range []struct {
		name, problem, install string
		already                bool
		want                   []string
	}{
		{"pinned driver changed", "DRIVER_HASH_NOT_EXPECTED", "", false, []string{"dependencies"}},
		{"installation declined", "", "INSTALL_DECLINED", false, []string{"dependencies", "prepare"}},
		{"new official install", "", "", false, []string{"dependencies", "prepare", "dependencies", "bind"}},
		{"already official stopped is supported", "", "", true, []string{"dependencies", "bind"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var calls []string
			ready := c.already
			runUnpairedProductPreparation(func() (bool, string) { calls = append(calls, "dependencies"); return ready, c.problem }, func() string { calls = append(calls, "prepare"); ready = true; return c.install }, func() string { calls = append(calls, "bind"); return "" })
			if !reflect.DeepEqual(calls, c.want) {
				t.Fatal(calls)
			}
		})
	}
}

func TestUnpairedProductCrashBeforeOriginalsOrOwnerCannotMutate(t *testing.T) {
	for stop := 0; stop < 5; stop++ {
		var calls []int
		steps := []func() error{}
		for i := 0; i < 4; i++ {
			index := i
			steps = append(steps, func() error {
				calls = append(calls, index)
				if stop == index {
					return fmt.Errorf("durable step %d failed", index)
				}
				return nil
			})
		}
		e := runUnpairedProductEnrollment(steps[0], steps[1], steps[2], steps[3])
		want := min(stop+1, 4)
		if len(calls) != want || (e != nil) != (stop < 4) {
			t.Fatal(stop, calls, e)
		}
		if stop < 3 && len(calls) > 3 {
			t.Fatal("mutation before explicit ON, durable originals and owner")
		}
	}
}

func TestUnpairedProductOffCrashOrderRetainsOriginalsAndChoice(t *testing.T) {
	for stop := 0; stop < 4; stop++ {
		choiceOn, originals, owner := true, true, true
		e := runUnpairedProductOff(func() error {
			if stop == 0 {
				return fmt.Errorf("OFF write/readback failed")
			}
			choiceOn = false
			return nil
		}, func() error {
			if choiceOn {
				t.Fatal("restoration preceded durable OFF")
			}
			if stop == 1 {
				return fmt.Errorf("native restoration failed")
			}
			originals = false
			return nil
		}, func() error {
			if originals {
				t.Fatal("owner removed before originals")
			}
			if stop == 2 {
				return fmt.Errorf("owner removal failed")
			}
			owner = false
			return nil
		})
		if (e != nil) != (stop < 3) || choiceOn != (stop == 0) || originals != (stop <= 1) || owner != (stop < 3) {
			t.Fatal(stop, e, choiceOn, originals, owner)
		}
	}
}

func TestUnpairedProductAdmissionCannotUseMemoryOrPartialNativeProof(t *testing.T) {
	p := unpairedProductDriverProof{true, true, true, true, true, true, true, true, true, true, true, 4, 2, 1, 3}
	if !p.valid() {
		t.Fatal("fresh stopped product owner rejected")
	}
	for i := 0; i < 11; i++ {
		q := p
		fields := []*bool{&q.configured, &q.enabled, &q.consentBound, &q.ownerExact, &q.storeProtected, &q.official, &q.native, &q.hash, &q.receipt, &q.receiptRoots, &q.serviceReadable}
		*fields[i] = false
		if q.valid() {
			t.Fatal("missing proof accepted", i)
		}
	}
	for _, q := range []unpairedProductDriverProof{func() unpairedProductDriverProof { q := p; q.state = 4; return q }(), func() unpairedProductDriverProof { q := p; q.start = 2; return q }(), func() unpairedProductDriverProof { q := p; q.originalStart = 4; return q }(), func() unpairedProductDriverProof { q := p; q.originalState = 2; return q }()} {
		if q.valid() {
			t.Fatal("unknown native service admitted")
		}
	}
}

func TestUnpairedProductDriverChangeHasVisibleRestorationInstruction(t *testing.T) {
	n := UnpairedProductDriverNotice("DRIVER_HASH_NOT_EXPECTED")
	if !strings.Contains(n, "重新開啟") || !strings.Contains(n, "官方 USB 驅動") || !strings.Contains(n, "保留") {
		t.Fatal(n)
	}
	if UnpairedProductDriverNotice("UNRELATED") != "" {
		t.Fatal("unknown diagnostic classified as driver mismatch")
	}
}

func TestUnpairedProductChoiceRequiresExplicitBoolean(t *testing.T) {
	for _, c := range []struct {
		data     string
		on, fail bool
	}{
		{`{"version":1,"enabled":true}`, true, false},
		{`{"version":1,"enabled":false}`, false, false},
		{`{"version":1}`, false, true},
		{`{"version":1,"enabled":null}`, false, true},
		{`{"version":1,"enabled":"false"}`, false, true},
		{`{"version":2,"enabled":false}`, false, true},
		{`{"version":1,"enabled":false,"unexpected":1}`, false, true},
		{`{"version":1,"enabled":false} {}`, false, true},
	} {
		on, e := decodeUnpairedProductChoice([]byte(c.data))
		if on != c.on || (e != nil) != c.fail {
			t.Fatal(c.data, on, e)
		}
	}
}
