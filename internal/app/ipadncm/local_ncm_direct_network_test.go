//go:build usblink_local_remote

package ipadncm

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"strings"
	"testing"
)

func TestLocalNCMDirectStartupObservationCannotAuthorizeOrTouchUSB(t *testing.T) {
	fn := unpairedSourceFunction(t, "local_ncm_direct_observation_windows.go", "observeOwnedDirectBinding")
	calls := unpairedCalls(fn)
	for _, forbidden := range []string{"inventory", "Inspect", "descriptor", "openAppleControl", "RunLocalNCMDirectNetwork", "RestoreLocalNCMDirect", "saveLocalNCMDirectJournal", "clearLocalNCMDirectJournal", "set", "masterChanged"} {
		if calls[forbidden] != 0 {
			t.Fatalf("read-only startup observation reaches %s", forbidden)
		}
	}
	if calls["readLocalNCMDirectJournal"] == 0 || calls["inventoryPnP"] == 0 || calls["configuredStartupNodeScope"] == 0 || calls["verifyDirectJournal"] == 0 || calls["readLocalNCMDirectJournal"] >= calls["inventoryPnP"] {
		t.Fatal("observation lacks protected scope and fresh journal checks")
	}
	ast.Inspect(fn, func(n ast.Node) bool {
		if a, ok := n.(*ast.AssignStmt); ok {
			for _, lhs := range a.Lhs {
				if s, ok := lhs.(*ast.SelectorExpr); ok {
					switch s.Sel.Name {
					case "issued", "issuedContext", "issuedRevision", "Requested", "Effective", "NetworkReady", "RecoveryRequired", "running", "master":
						t.Fatalf("observation mutates authority/readiness: %s", s.Sel.Name)
					}
				}
			}
		}
		return true
	})
}

func TestLocalNCMDirectBindingDiagnosticPreservesGate(t *testing.T) {
	for mask := 0; mask < 32; mask++ {
		id, service, inf := `USB\VID_05AC&PID_12AB&MI_00`, "UsbNcm", "usbncm.inf"
		var lower, upper []string
		if mask&1 != 0 {
			id += "&NCM"
		}
		if mask&2 != 0 {
			service = "WinUSB"
		}
		if mask&4 != 0 {
			inf = "oem44.inf"
		}
		if mask&8 != 0 {
			lower = []string{"AppleLowerFilter"}
		}
		if mask&16 != 0 {
			upper = []string{"WUDFRd"}
		}
		d := directBindingProof(id, service, inf, lower, upper, nil)
		if (d.Failure == "") != (mask == 0) {
			t.Fatalf("old binding gate changed for mask %d: %+v", mask, d)
		}
		want := ""
		switch {
		case mask&1 != 0:
			want = "DIRECT_NCM_ID_PREFIX_UNPROVEN"
		case mask&2 != 0:
			want = "DIRECT_NCM_SERVICE_BINDING_UNPROVEN"
		case mask&4 != 0:
			want = "DIRECT_NCM_CACHED_INF_UNPROVEN"
		case mask&8 != 0:
			want = "DIRECT_NCM_LOWER_FILTERS_PRESENT"
		case mask&16 != 0:
			want = "DIRECT_NCM_UPPER_FILTERS_PRESENT"
		}
		if d.Failure != want {
			t.Fatalf("wrong failed subcheck: %+v", d)
		}
	}
	if d := directBindingProof(`usb\vid_05ac&pid_12ab&mi_00`, "USBNCM", "USBNCM.INF", nil, nil, nil); d.Failure != "" {
		t.Fatalf("case-insensitive binding rejected: %+v", d)
	}
	if d := directBindingProof(`USB\VID_05AC&PID_12AB&REV_1000&MI_00`, "UsbNcm", "usbncm.inf", nil, nil, nil); d.IDShape != "revision_mi00" || d.Failure != "DIRECT_NCM_REVISION_UNPROVEN" {
		t.Fatalf("unknown descriptor revision admitted or hidden: %+v", d)
	}
}

func TestLocalNCMDirectRevisionPrefixRequiresExactBoundDeviceVersion(t *testing.T) {
	revision := uint16(0x1316)
	valid := `USB\VID_05AC&PID_12AB&REV_1316&MI_00`
	for _, id := range []string{valid, strings.ToLower(valid)} {
		d := directBindingProof(id, "UsbNcm", "usbncm.inf", nil, nil, &revision)
		if d.Failure != "" || d.IDShape != "revision_mi00" || !d.RevisionVerified {
			t.Fatalf("valid bound revision rejected: %+v", d)
		}
	}
	for _, bad := range []string{
		valid + "&NCM", valid + `\INSTANCE`, valid + " ", " " + valid,
		strings.Replace(valid, "05AC", "05AD", 1), strings.Replace(valid, "12AB", "1903", 1),
		strings.Replace(valid, "MI_00", "MI_01", 1), strings.Replace(valid, "1316", "1317", 1),
		strings.Replace(valid, "1316", "131", 1), strings.Replace(valid, "1316", "01316", 1),
		strings.Replace(valid, "1316", "13G6", 1), strings.Replace(valid, "1316", "+316", 1),
		strings.Replace(valid, "&REV_1316&MI_00", "&MI_00&REV_1316", 1),
		strings.Replace(valid, "1316", "1316&REV_1316", 1),
	} {
		if d := directBindingProof(bad, "UsbNcm", "usbncm.inf", nil, nil, &revision); d.Failure == "" {
			t.Fatalf("malformed/different revision admitted: %q", bad)
		}
	}
	// A legitimate REV does not replace official driver/filter checks.
	for _, d := range []directBindingEvidence{
		directBindingProof(valid, "WinUSB", "usbncm.inf", nil, nil, &revision),
		directBindingProof(valid, "UsbNcm", "oem44.inf", nil, nil, &revision),
		directBindingProof(valid, "UsbNcm", "usbncm.inf", []string{"other"}, nil, &revision),
		directBindingProof(valid, "UsbNcm", "usbncm.inf", nil, []string{"other"}, &revision),
	} {
		if d.Failure == "" {
			t.Fatal("REV bypassed driver binding", d)
		}
	}
}

func TestLocalNCMDirectBindingDiagnosticIsBoundedAndPrivate(t *testing.T) {
	secret := `C:\private\device-serial`
	d := directBindingProof(secret, secret, secret, []string{secret, secret, secret}, []string{secret}, nil)
	b, err := json.Marshal(d)
	if err != nil || len(b) > 800 || strings.Contains(string(b), "private") || strings.Contains(string(b), "device-serial") || d.LowerCount != 3 || d.UpperCount != 1 {
		t.Fatalf("unsafe binding projection: %s %v", b, err)
	}
	if empty := directBindingProof("", "", "", nil, nil, nil); empty.INF != "unavailable" || empty.Service != "unavailable" {
		t.Fatalf("missing cached data presented as known: %+v", empty)
	}
	c := newLocalNCMDirectController()
	c.state.Binding = &d
	c.state.Network = &directNetworkEvidence{PeerStage: "verifying"}
	snapshot := c.snapshot()
	snapshot.Binding.Failure = "mutated"
	snapshot.Network.PeerStage = "mutated"
	if c.snapshot().Binding.Failure == "mutated" {
		t.Fatal("snapshot aliases live binding")
	}
	if c.snapshot().Network.PeerStage == "mutated" {
		t.Fatal("snapshot aliases live network")
	}
	for _, unsafe := range []string{secret, strings.Repeat("X", 97), "ERROR: private"} {
		if directEvidenceCode(unsafe) != "OTHER" {
			t.Fatal("unbounded or private status exported")
		}
	}
	if directEvidenceCode("PEER_PREPARATION_CANCELLED") != "PEER_PREPARATION_CANCELLED" {
		t.Fatal("fixed peer reason lost")
	}
}

func TestLocalNCMDirectCDCCollectionRequiresExactShapeAndRevision(t *testing.T) {
	revision := uint16(0x1316)
	valid := `USB\VID_05AC&PID_12AB&REV_1316&CDC_0D&MI_00`
	for _, id := range []string{valid, strings.ToLower(valid)} {
		d := directBindingProof(id, "UsbNcm", "usbncm.inf", nil, nil, &revision)
		if d.Failure != "" || d.IDShape != "revision_cdc0d_mi00" || !d.RevisionVerified || d.DescriptorBCD != "1316" {
			t.Fatalf("exact CDC collection rejected: %+v", d)
		}
		if d.IDTokens.Tokens != ([5]string{"VID_05AC", "PID_12AB", "REV_1316", "CDC_0D", "MI_00"}) || d.IDTokens.Unknown != 0 || d.IDTokens.Duplicates != 0 {
			t.Fatalf("exact CDC tokens lost: %+v", d.IDTokens)
		}
	}
	for _, bad := range []string{
		valid + "&NCM", valid + `\private-serial`, valid + " ", " " + valid,
		strings.Replace(valid, "05AC", "05AD", 1), strings.Replace(valid, "12AB", "1903", 1),
		strings.Replace(valid, "CDC_0D", "CDC_02", 1), strings.Replace(valid, "CDC_0D", "CDC_D", 1),
		strings.Replace(valid, "CDC_0D", "CDC_00D", 1), strings.Replace(valid, "CDC_0D", "CDC_GD", 1),
		strings.Replace(valid, "CDC_0D", "CDC_0D&CDC_0D", 1),
		strings.Replace(valid, "MI_00", "MI_01", 1), strings.Replace(valid, "MI_00", "MI_02", 1),
		strings.Replace(valid, "REV_1316", "REV_1317", 1), strings.Replace(valid, "REV_1316&", "", 1),
		strings.Replace(valid, "REV_1316&CDC_0D", "CDC_0D&REV_1316", 1),
		strings.Replace(valid, "CDC_0D&MI_00", "MI_00&CDC_0D", 1),
		strings.Replace(valid, "REV_1316", "REV_1316&REV_1316", 1),
		strings.Replace(valid, "VID", "VıD", 1),
	} {
		if d := directBindingProof(bad, "UsbNcm", "usbncm.inf", nil, nil, &revision); d.Failure == "" {
			t.Fatalf("nonmatching CDC collection admitted: %q", bad)
		}
	}
	if d := directBindingProof(valid, "UsbNcm", "usbncm.inf", nil, nil, nil); d.Failure != "DIRECT_NCM_REVISION_UNPROVEN" {
		t.Fatalf("startup observation granted unknown revision: %+v", d)
	}
	if d := directBindingProof(valid, "UsbNcm", "oem99.inf", nil, nil, &revision); d.Failure != "DIRECT_NCM_CACHED_INF_UNPROVEN" {
		t.Fatal("CDC shape bypassed driver proof", d)
	}
}

func TestLocalNCMDirectIDTokensNeverExportInstancesOrUnknownText(t *testing.T) {
	id := `USB\VID_05AC&PID_12AB&REV_1316&SECRET_private&CDC_0D&MI_00&MI_00\private-serial`
	d := directIDTokens(id)
	b, err := json.Marshal(d)
	if err != nil || strings.Contains(strings.ToLower(string(b)), "private") || strings.Contains(string(b), "SECRET") || len(b) > 350 {
		t.Fatalf("unsafe prefix evidence: %s %v", b, err)
	}
	if d.Count != 7 || d.Unknown != 1 || d.Duplicates != 1 || d.Omitted != 2 || !d.InstanceSuffix || d.Tokens[3] != "OTHER" {
		t.Fatalf("unknown, duplicate or omitted tokens hidden: %+v", d)
	}
	if long := directIDTokens(strings.Repeat("X", 257)); !long.Truncated || long.Count != 0 {
		t.Fatalf("oversize prefix scanned: %+v", long)
	}
}

func measuredDirectConfiguration() Configuration {
	h, n, m := uint16(0x110), uint16(0x100), uint16(16014)
	capabilities := byte(187)
	return Configuration{Value: 1, NCMControls: 1, Interfaces: []Interface{
		{Number: 0, Class: 2, Subclass: 13, Endpoints: []Endpoint{{Address: 0x81, Type: 3, MaxPacket: 16}}, Slaves: []byte{1}, Functions: []FunctionalDescriptor{{Subtype: 0, Length: 5, Version: &h}, {Subtype: 15, Length: 13, MaxSegment: &m}, {Subtype: 26, Length: 6, Version: &n, Capabilities: &capabilities}}},
		{Number: 1, Class: 10, Protocol: 1},
		{Number: 1, Alternate: 1, Class: 10, Protocol: 1, Endpoints: []Endpoint{{Address: 0x82, Type: 2, MaxPacket: 512}, {Address: 1, Type: 2, MaxPacket: 512}}},
	}}
}

func TestLocalNCMDirectNetworkAdmitsOnlyMeasuredCompleteTopology(t *testing.T) {
	c := measuredDirectConfiguration()
	if !directNetworkTopology([]Configuration{c}, 1) {
		t.Fatal("measured direct layout rejected")
	}
	if networkUSBPreflight([]Configuration{c}, 1) {
		t.Fatal("public mode3 whitelist was widened")
	}
	for name, mutate := range map[string]func(*Configuration){
		"mode is not configuration":   func(c *Configuration) { c.Value = 5 },
		"missing interrupt":           func(c *Configuration) { c.Interfaces[0].Endpoints = nil },
		"extra control":               func(c *Configuration) { c.NCMControls = 2 },
		"wrong union":                 func(c *Configuration) { c.Interfaces[0].Slaves = []byte{3} },
		"missing ethernet descriptor": func(c *Configuration) { c.Interfaces[0].Functions = c.Interfaces[0].Functions[:1] },
		"no data IN":                  func(c *Configuration) { c.Interfaces[2].Endpoints[0].Address = 2 },
		"duplicates":                  func(c *Configuration) { c.Interfaces[2] = c.Interfaces[1] },
		"photo present":               func(c *Configuration) { c.Interfaces = append(c.Interfaces, Interface{Class: 6}) },
		"mux present":                 func(c *Configuration) { c.Interfaces = append(c.Interfaces, Interface{Class: 255, Subclass: 254}) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := cloneDirectConfigurations([]Configuration{c})[0]
			mutate(&bad)
			if directNetworkTopology([]Configuration{bad}, 1) {
				t.Fatal("unsafe topology admitted")
			}
		})
	}
}

func TestLocalNCMDirectNetworkNeverCallsDriverStartNetworkReady(t *testing.T) {
	if directIPv4Ready(0, false, "") || directIPv4Ready(1, false, "") || directIPv4Ready(0, true, "") || directIPv4Ready(1, true, "changed") {
		t.Fatal("unverified network admitted")
	}
	if !directIPv4Ready(1, true, "") {
		t.Fatal("DHCP plus exact IPv4 peer not admitted")
	}
}

func TestLocalNCMDirectOffCancelsActiveSessionEvenWhenSaveFails(t *testing.T) {
	for _, masterOff := range []bool{false, true} {
		c := newLocalNCMDirectController()
		c.master = true
		c.ctx = context.Background()
		ctx, cancel := context.WithCancel(context.Background())
		c.sessionCancel = cancel
		c.running = true
		c.state.Effective = true
		c.state.NetworkReady = true
		c.state.RecoveryRequired = true
		c.configure(func(bool) error { return errors.New("disk unavailable") }, nil)
		if masterOff {
			c.masterChanged(false)
		} else {
			if e := c.set(false, strings.Repeat("f", 32)); e != nil {
				t.Fatal(e)
			}
		}
		select {
		case <-ctx.Done():
		default:
			t.Fatal("OFF failed to cancel network synchronously")
		}
		if s := c.snapshot(); s.Effective || s.NetworkReady || s.Phase != "direct_network_stopping" || !s.RecoveryRequired {
			t.Fatalf("OFF must revoke ready immediately without claiming recovery: %+v", s)
		}
		if !masterOff {
			waitDirectState(t, c, func(s localNCMDirectStatus) bool { return s.Persistence == "failed" })
		}
	}
}
