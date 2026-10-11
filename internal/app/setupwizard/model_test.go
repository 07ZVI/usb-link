package setupwizard

import (
	"reflect"
	"testing"
)

func TestLicenseBlocksEveryRouteToInstallation(t *testing.T) {
	m := Model{}
	if !m.Next() || m.Page != License || m.Next() {
		t.Fatal("license was bypassed")
	}
	m.Accepted = true
	for m.Page < Ready {
		if !m.Next() {
			t.Fatal("cannot proceed")
		}
	}
	if !m.Back() || !m.Back() || m.Page != License {
		t.Fatal("cannot revisit license")
	}
	m.Accepted = false
	if m.Next() {
		t.Fatal("revoked agreement was accepted")
	}
	m.Page = Ready
	if m.Next() {
		t.Fatal("ready page bypassed revoked agreement")
	}
	m.Accepted = true
	if !m.Next() || m.Page != Installing || m.Back() || m.Next() {
		t.Fatal("installation must own navigation")
	}
}

func TestOnlySelectedOptionalComponentsArePrepared(t *testing.T) {
	cases := []struct {
		o    Options
		want []string
	}{
		{Options{}, []string{"wintun", "dotnet"}},
		{Options{IPad: true}, []string{"wintun", "dotnet", "apple-support", "apple-driver"}},
		{Options{MacTools: true}, []string{"wintun", "dotnet", "zadig"}},
		{Options{IPad: true, MacTools: true}, []string{"wintun", "dotnet", "apple-support", "apple-driver", "zadig"}},
	}
	for _, c := range cases {
		if !reflect.DeepEqual(c.o.Dependencies(), c.want) {
			t.Fatalf("%+v selected wrong packages", c.o)
		}
	}
}
