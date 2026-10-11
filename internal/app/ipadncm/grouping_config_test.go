package ipadncm

import "testing"

func TestGroupingTrialOnlyAcceptsObservedUnionLayout(t *testing.T) {
	fixture := func() Configuration {
		b := config([]byte{9, 4, 2, 0, 1, 2, 13, 0, 0}, []byte{5, 0x24, 6, 2, 3}, []byte{9, 4, 3, 1, 2, 10, 0, 1, 0}, []byte{7, 5, 0x85, 2, 0, 4, 0}, []byte{7, 5, 3, 2, 0, 4, 0}, []byte{9, 4, 4, 0, 0, 2, 13, 0, 0}, []byte{5, 0x24, 6, 4, 5}, []byte{9, 4, 5, 1, 2, 10, 0, 1, 0}, []byte{7, 5, 0x86, 2, 0, 4, 0}, []byte{7, 5, 4, 2, 0, 4, 0})
		c, e := Parse(b, 4)
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	if !groupingTrialConfig(fixture()) {
		t.Fatal("observed topology rejected")
	}
	for _, change := range []func(*Configuration){
		func(c *Configuration) { c.Value = 3 },
		func(c *Configuration) { c.Associations = []Association{{First: 2, Count: 2}} },
		func(c *Configuration) { c.Interfaces[0].Slaves = []byte{5} },
		func(c *Configuration) { c.Interfaces[2].Slaves = nil },
		func(c *Configuration) { c.Interfaces[3].Endpoints = c.Interfaces[3].Endpoints[:1] },
		func(c *Configuration) { c.Interfaces[3].Endpoints[0].Address = 3 },
	} {
		c := fixture()
		change(&c)
		if groupingTrialConfig(c) {
			t.Fatalf("unqualified config accepted: %+v", c)
		}
	}
}
