package ncm

import (
	"encoding/hex"
	"testing"
)

func capturedSplitEvidence(t *testing.T) ([]byte, InterfaceDescriptor, InterfaceDescriptor, []PipeDescriptor) {
	t.Helper()
	// Exact 47-byte control view and QueryInterfaceSettings/QueryPipe results
	// from the user's Windows 0.2.3 log on 2026-10-01 at 17:16:14.
	b, err := hex.DecodeString("09022f00010100c0000904000000020d0006052400100105240600010d240f05000000008e3e00000006241a0001bb")
	if err != nil {
		t.Fatal(err)
	}
	alt0 := InterfaceDescriptor{9, 4, 1, 0, 0, 10, 0, 1, 7}
	alt1 := InterfaceDescriptor{9, 4, 1, 1, 2, 10, 0, 1, 7}
	pipes := []PipeDescriptor{{2, 0x81, 1024, 0}, {2, 1, 1024, 0}}
	return b, alt0, alt1, pipes
}

func TestCapturedSeparateWinUSBInterfaces(t *testing.T) {
	b, alt0, alt1, pipes := capturedSplitEvidence(t)
	// The strict single-view parser must still reject incomplete evidence.
	if _, err := ParseFunction(b, 0); err == nil {
		t.Fatal("single-view parser accepted absent data interface")
	}
	f, err := ParsePairedFunction(b, 0, alt0, alt1, pipes)
	if err != nil || f.Data != 1 || f.MACIndex != 5 || f.MaxSegment != 16014 || f.Capabilities != 0xbb {
		t.Fatalf("f=%+v err=%v", f, err)
	}
	for i := range b {
		if _, err := ParsePairedFunction(b[:i], 0, alt0, alt1, pipes); err == nil {
			t.Fatal("accepted truncated split view", i)
		}
	}
}

func TestSplitEvidenceRejectsWrongPairOrPipes(t *testing.T) {
	for _, name := range []string{"wrong-interface", "wrong-alt", "wrong-class", "wrong-protocol", "alt0-endpoint", "missing-out", "interrupt", "duplicate-in", "zero-packet", "zero-endpoint", "wrong-union", "missing-header"} {
		t.Run(name, func(t *testing.T) {
			b, a0, a1, pipes := capturedSplitEvidence(t)
			switch name {
			case "wrong-interface":
				a1.Number = 3
			case "wrong-alt":
				a1.Alt = 0
			case "wrong-class":
				a1.Class = 3
			case "wrong-protocol":
				a1.Protocol = 2
			case "alt0-endpoint":
				a0.Endpoints = 1
			case "missing-out":
				pipes = pipes[:1]
			case "interrupt":
				pipes[1].Type = 3
			case "duplicate-in":
				pipes[1].ID = 0x82
			case "zero-packet":
				pipes[1].MaxPacket = 0
			case "zero-endpoint":
				pipes[1].ID = 0
			case "wrong-union":
				b[27] = 3
			case "missing-header":
				b[20] = 0x7f
			}
			if _, err := ParsePairedFunction(b, 0, a0, a1, pipes); err == nil {
				t.Fatal("accepted invalid evidence")
			}
		})
	}
}

func TestFullConfigurationMustAgreeWithPairedQueries(t *testing.T) {
	b, a0, a1, pipes := capturedSplitEvidence(t)
	b = append(b, 9, 4, 1, 0, 0, 10, 0, 1, 7, 9, 4, 1, 1, 2, 10, 0, 1, 7)
	b[2], b[3], b[4] = byte(len(b)), 0, 2
	if _, err := ParsePairedFunction(b, 0, a0, a1, pipes); err != nil {
		t.Fatal(err)
	}
	b[len(b)-2] = 0 // conflicting protocol in the configuration view
	if _, err := ParsePairedFunction(b, 0, a0, a1, pipes); err == nil {
		t.Fatal("accepted descriptor/query conflict")
	}
}
