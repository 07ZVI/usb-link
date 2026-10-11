package interfaceconfig

import "testing"

func TestDADFactoryMappedClaimIsNotSameGUIDAdoption(t *testing.T) {
	old := Scope{"host", HostGUID, 7, 9}
	current := Scope{"host", HostGUID, 8, 10}
	p := persistentOriginal{Scope: old, OriginalMTU: 1500, DesiredMTU: 1500, AddressAbsent: true, Address: "10.6.9.1", Prefix: 32, Profile: &profileOriginal{MacGUID, 0}, AppliedAddress: &addressBaseline{"infinite", "infinite"}}
	d := dadOriginal{old, 1}
	sha := persistentDigest(p)
	for _, v := range []uint32{0, 1} {
		if e := validateDADFactoryOriginal(old, current, sha, p, d, v); e != nil {
			t.Fatal(e)
		}
	}
	later := d
	later.Scope.Index = 12
	later.Scope.LUID = 13
	if e := validateDADFactoryOriginal(later.Scope, current, sha, p, later, 0); e != nil {
		t.Fatal("independent later DAD scope must not rewrite first persistent baseline", e)
	}
	for _, change := range []func(*Scope, *Scope, *persistentOriginal, *dadOriginal, *string, *uint32){func(o, c *Scope, p *persistentOriginal, d *dadOriginal, s *string, v *uint32) { *v = 2 }, func(o, c *Scope, p *persistentOriginal, d *dadOriginal, s *string, v *uint32) { d.Scope.LUID++ }, func(o, c *Scope, p *persistentOriginal, d *dadOriginal, s *string, v *uint32) { c.GUID = MacGUID }, func(o, c *Scope, p *persistentOriginal, d *dadOriginal, s *string, v *uint32) { c.Role = "ipad" }, func(o, c *Scope, p *persistentOriginal, d *dadOriginal, s *string, v *uint32) { p.OriginalMTU = 9000 }, func(o, c *Scope, p *persistentOriginal, d *dadOriginal, s *string, v *uint32) { p.Profile = nil }} {
		o, c, b, x, s, v := old, current, p, d, sha, uint32(0)
		change(&o, &c, &b, &x, &s, &v)
		if validateDADFactoryOriginal(o, c, s, b, x, v) == nil {
			t.Fatal("unproven original accepted")
		}
	}
}

func TestDADProjectionNeverAuthorizesNewLUIDOrForeignGUID(t *testing.T) {
	old := Scope{"host", HostGUID, 7, 9}
	fresh := Scope{"host", HostGUID, 8, 9}
	if validateDADProjection(old, fresh) != nil {
		t.Fatal("sameLUID freshindex projection rejected")
	}
	for _, bad := range []Scope{{"host", HostGUID, 8, 10}, {"mac", MacGUID, 8, 9}, {"ipad", HostGUID, 8, 9}, {"host", HostGUID, 0, 9}} {
		if validateDADProjection(old, bad) == nil {
			t.Fatal("unknown mapping adopted", bad)
		}
	}
}
