package ncm

import (
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"
)

// The 18-byte device descriptor is synthetic but shaped like the Mac's
// (05ac:1903); the configuration view is the captured 47-byte control view.
func summaryDevice() []byte {
	return []byte{18, 1, 0, 2, 0, 0, 0, 64, 0xac, 0x05, 0x03, 0x19, 0x10, 0x05, 1, 2, 3, 1}
}

func TestSummaryOfCapturedMacControlView(t *testing.T) {
	b, alt0, alt1, pipes := capturedSplitEvidence(t)
	s := SummarizeDescriptors(summaryDevice(), b, 0, alt0, alt1, pipes)
	want := "device{vid=05ac pid=1903 bcdDevice=0x0510 class=00/00/00 ep0=64 configurations=1}" +
		" config{value=1 attributes=0xc0 max_power=0mA total_length=47 interfaces=1 scoped_view=yes malformed=no}" +
		" iad{present=no}" +
		" control{interface=0 alt0{class=02/0d/00 declared=0 ep=none} interrupt_in=no}" +
		" cdc{header=yes(bcdCDC=0x0110) union=yes(master=0 slaves=[1]) ethernet=yes(iMACAddress_present=yes wMaxSegmentSize=16014 bmEthernetStatistics=0x00000000 wNumberMCFilters=0x0000 bNumberPowerFilters=0) ncm=yes(bcdNcmVersion=0x0100 bmNetworkCapabilities=0xbb)}" +
		" data{interface=1 config_view=none queried=alt0{class=0a/00/01 declared=0} alt1{class=0a/00/01 declared=2} pipes_alt1=0x81:bulk:max1024:iv0,0x01:bulk:max1024:iv0 bulk_in=yes bulk_out=yes}"
	if got := s.String(); got != want {
		t.Fatalf("summary changed\n got: %s\nwant: %s", got, want)
	}
	if s.ControlInterruptIn() || len(s.IADs) != 0 || s.Configurations != 1 || s.MACIndex != 5 {
		t.Fatalf("%+v", s)
	}
}

func fullConfiguration(t *testing.T) []byte {
	t.Helper()
	// IAD + control interface with an interrupt IN endpoint + data interface
	// with both alternate settings, the layout Windows' inbox UsbNcm expects.
	raw := "09026f00020100c0fa" +
		"080b0002020d0000" + // IAD: interfaces 0..1, class 02/0d/00
		"0904000001020d0000" + // control interface, one endpoint
		"0524001001" + "0524060001" + "0d240f04000000008e3e000000" + "06241a0001bb" +
		"07058103" + "1000" + "10" + // interrupt IN 0x81, max 16, interval 16
		"09040100000a000100" +
		"09040101020a000100" +
		"07058202" + "0002" + "00" + "07050202" + "0002" + "00"
	raw = strings.ReplaceAll(raw, " ", "")
	b, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatal(err)
	}
	b[2] = byte(len(b))
	return b
}

func TestSummaryOfInboxStyleLayoutReportsIADInterruptAndAlts(t *testing.T) {
	b := fullConfiguration(t)
	alt0 := InterfaceDescriptor{9, 4, 1, 0, 0, 10, 0, 1, 0}
	alt1 := InterfaceDescriptor{9, 4, 1, 1, 2, 10, 0, 1, 0}
	s := SummarizeDescriptors(summaryDevice(), b, 0, alt0, alt1, []PipeDescriptor{{2, 0x82, 512, 0}, {2, 2, 512, 0}})
	if len(s.IADs) != 1 || s.IADs[0] != (IADSummary{0, 2, 2, 0x0d, 0}) {
		t.Fatalf("IAD %+v", s.IADs)
	}
	if !s.ControlInterruptIn() || len(s.ControlAlts) != 1 || s.ControlAlts[0].Endpoints[0] != (EndpointSummary{0x81, 3, 16, 16}) {
		t.Fatalf("control %+v", s.ControlAlts)
	}
	if len(s.DataAlts) != 2 || s.DataAlts[0].Declared != 0 || s.DataAlts[1].Declared != 2 || len(s.DataAlts[1].Endpoints) != 2 {
		t.Fatalf("data alts %+v", s.DataAlts)
	}
	text := s.String()
	for _, part := range []string{"iad{present=yes first=0 count=2 class=02/0d/00}", "ep=0x81:int:max16:iv16", "interrupt_in=yes",
		"alt1{class=0a/00/01 declared=2 ep=0x82:bulk:max512:iv0,0x02:bulk:max512:iv0}", "bulk_in=yes bulk_out=yes", "wMaxSegmentSize=16014"} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %q in %s", part, text)
		}
	}
}

func TestSummaryReportsMissingFunctionPartsWithoutInventingThem(t *testing.T) {
	b, alt0, alt1, _ := capturedSplitEvidence(t)
	// Drop the NCM functional descriptor and all pipes; zero the MAC string index.
	b = b[:len(b)-6]
	b[2] = byte(len(b))
	b[31] = 0
	s := SummarizeDescriptors(nil, b, 0, alt0, alt1, nil)
	text := s.String()
	for _, part := range []string{"device{unavailable}", "ncm=no", "iMACAddress_present=no", "pipes_alt1=none bulk_in=no bulk_out=no"} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing %q in %s", part, text)
		}
	}
}

func TestSummaryNeverPanicsOnTruncatedOrRandomInput(t *testing.T) {
	b, alt0, alt1, pipes := capturedSplitEvidence(t)
	full := fullConfiguration(t)
	for _, src := range [][]byte{b, full} {
		for i := 0; i <= len(src); i++ {
			s := SummarizeDescriptors(summaryDevice()[:min(i, 18)], src[:i], 0, alt0, alt1, pipes)
			_ = s.String()
		}
	}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 2000; i++ {
		junk := make([]byte, r.Intn(120))
		r.Read(junk)
		if len(junk) > 9 && i%2 == 0 {
			junk[0], junk[1] = 9, 2
		}
		s := SummarizeDescriptors(junk, junk, byte(r.Intn(4)), alt0, alt1, nil)
		if line := s.String(); strings.ContainsAny(line, "\r\n") || len(line) > 2048 {
			t.Fatalf("summary is not one bounded line: %q", line)
		}
	}
}

func TestSummaryBoundsRepeatedDescriptors(t *testing.T) {
	b := []byte{9, 2, 0, 0, 1, 1, 0, 0xc0, 0}
	for i := 0; i < 40; i++ {
		b = append(b, 9, 4, 0, byte(i), 8, 2, 0x0d, 0, 0)
		for j := 0; j < 20; j++ {
			b = append(b, 7, 5, 0x81, 3, 8, 0, 10)
		}
		b = append(b, 8, 0x0b, 0, 2, 2, 0x0d, 0, 0)
	}
	b[2], b[3] = byte(len(b)), byte(len(b)>>8)
	s := SummarizeDescriptors(summaryDevice(), b, 0, InterfaceDescriptor{}, InterfaceDescriptor{}, nil)
	if len(s.IADs) != summaryMaxIADs || len(s.ControlAlts) != summaryMaxAlts || len(s.ControlAlts[0].Endpoints) != summaryMaxEndpoints {
		t.Fatalf("unbounded summary: %d IAD %d alts", len(s.IADs), len(s.ControlAlts))
	}
}

func TestSummaryContainsNoIdentityText(t *testing.T) {
	b, alt0, alt1, pipes := capturedSplitEvidence(t)
	text := SummarizeDescriptors(summaryDevice(), b, 0, alt0, alt1, pipes).String()
	if strings.Contains(text, "raw=") || strings.Contains(strings.ToLower(text), "serial") {
		t.Fatal("summary may only carry fixed numeric fields")
	}
}
