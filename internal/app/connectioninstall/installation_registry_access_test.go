package connectioninstall

import "testing"

func TestRegistryReadOnlyRightsAreNotMutation(t *testing.T) {
	for _, mask := range []uint32{0, 0x80000000, 0x20000000, 0xa0000000, 0x20019, 0x20000, 0x1, 0x8, 0x10} {
		if registryAccessCanMutate(mask) {
			t.Fatalf("read-only mask %08x rejected", mask)
		}
	}
}
func TestEveryRegistryMutationRightIsDetected(t *testing.T) {
	for _, mask := range []uint32{0x40000000, 0x10000000, 0x2, 0x4, 0x20, 0x10000, 0x40000, 0x80000, 0x20006, 0xf003f, 0x80040000, 0x20000020} {
		if !registryAccessCanMutate(mask) {
			t.Fatalf("write mask %08x accepted", mask)
		}
	}
}
func TestOnlyExactPrivilegedRegistryWritersAreAllowed(t *testing.T) {
	admin := "S-1-5-21-10-20-30-1001"
	for _, sid := range []string{"S-1-5-18", "S-1-5-32-544", admin} {
		if !trustedDeletedRegistryWriter(sid, admin) {
			t.Fatal(sid)
		}
	}
	for _, sid := range []string{"S-1-5-13", "S-1-5-32-545", "S-1-1-0", "S-1-5-11", "S-1-5-21-10-20-30-1002", "S-1-5-80-123", ""} {
		if trustedDeletedRegistryWriter(sid, admin) {
			t.Fatal("unrelated writer accepted", sid)
		}
	}
	if trustedDeletedRegistryWriter(admin, "") {
		t.Fatal("user accepted without elevated-token proof")
	}
}

func TestReportedTerminalServerACEOnlyAllowsLegacyDiscard(t *testing.T) {
	if !removableLegacyRegistryACE("S-1-5-13", "", 0x3001f, 0x10) {
		t.Fatal("reported inherited legacy compatibility ACE blocks cleanup")
	}
	for _, sid := range []string{"S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-13-1", ""} {
		if removableLegacyRegistryACE(sid, "", 0x3001f, 0x10) {
			t.Fatalf("unreviewed principal accepted: %s", sid)
		}
	}
	for _, flags := range []byte{0, 1, 2, 8, 0x12, 0x18, 0x90} {
		if removableLegacyRegistryACE("S-1-5-13", "", 0x3001f, flags) {
			t.Fatalf("unreviewed ACE flags accepted: %02x", flags)
		}
	}
	for _, mask := range []uint32{0xf003f, 0x3003f, 0x7001f, 0xb001f, 0x4003001f, 0x1003001f} {
		if removableLegacyRegistryACE("S-1-5-13", "", mask, 0x10) {
			t.Fatalf("additional privileges accepted: %08x", mask)
		}
	}
}

func TestServiceReadDoesNotGrantStartOrConfiguration(t *testing.T) {
	for _, mask := range []uint32{0x80000000, 0x2008d, 0x20000, 0x1, 0x4, 0x8, 0x80} {
		if serviceAccessCanChangeCore(mask) {
			t.Fatalf("service query mask %08x rejected", mask)
		}
	}
	for _, mask := range []uint32{0x40000000, 0x20000000, 0x10000000, 0x2, 0x10, 0x20, 0x10000, 0x40000, 0x80000, 0xf01ff, 0x80000010} {
		if !serviceAccessCanChangeCore(mask) {
			t.Fatalf("service control mask %08x accepted", mask)
		}
	}
	if registryAccessCanMutate(0x20000000) || !serviceAccessCanChangeCore(0x20000000) {
		t.Fatal("generic execute mappings confused between objects")
	}
}
