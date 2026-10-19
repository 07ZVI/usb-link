//go:build usblink_local_remote

package ipadncm

import (
	"errors"
	"strings"
	"testing"
	"time"

	"suhang/usbnet/internal/transport/ncm"
)

func waitMTUCap(t *testing.T, c *localMacMTUCapController, persistence string) localMacMTUCapStatus {
	t.Helper()
	for i := 0; i < 400; i++ {
		if s := c.snapshot(); s.Persistence == persistence && !s.Busy {
			return s
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timeout", c.snapshot())
	return localMacMTUCapStatus{}
}

func TestMacMTUCapIsAutoWithoutMasterAndRejectsRequests(t *testing.T) {
	c := newLocalMacMTUCapController()
	if c.effective() != ncm.MTUCapAuto {
		t.Fatal("default must be auto")
	}
	id := strings.Repeat("a", 32)
	if err := c.set("1500", id); err == nil || c.snapshot().RejectedID != id || c.effective() != ncm.MTUCapAuto {
		t.Fatal("request without the master switch must be rejected", err)
	}
	for _, bad := range []struct{ setting, id string }{{"1500", "short"}, {"1500", strings.Repeat("z", 32)}, {"16000", id}} {
		c.masterChanged(true)
		if c.set(bad.setting, bad.id) == nil {
			t.Fatal("invalid request accepted", bad)
		}
	}
}

func TestMacMTUCapRoundTripAndMasterGating(t *testing.T) {
	stored := "auto"
	c := newLocalMacMTUCapController()
	c.configure(func(v string) error { stored = v; return nil }, func() (string, error) { return stored, nil })
	c.masterChanged(true)
	waitMTUCap(t, c, "saved")
	for _, want := range []ncm.MTUCap{ncm.MTUCap9000, ncm.MTUCap1500, ncm.MTUCapAuto} {
		id := strings.Repeat("b", 32)
		if err := c.set(want.String(), id); err != nil {
			t.Fatal(err)
		}
		s := waitMTUCap(t, c, "saved")
		if s.RequestID != id || stored != want.String() || s.SavedCap != want.String() || s.EffectiveCap != want.String() || c.effective() != want {
			t.Fatal(want, s, stored)
		}
	}
	_ = c.set("9000", strings.Repeat("c", 32))
	waitMTUCap(t, c, "saved")
	c.masterChanged(false)
	if s := c.snapshot(); c.effective() != ncm.MTUCapAuto || s.EffectiveCap != "auto" || s.SavedCap != "9000" {
		t.Fatal("master off must behave as auto but keep the preference", s)
	}
	// A restart reads the saved preference back once the master is on again.
	c2 := newLocalMacMTUCapController()
	c2.configure(nil, func() (string, error) { return stored, nil })
	c2.masterChanged(true)
	waitMTUCap(t, c2, "saved")
	if c2.effective() != ncm.MTUCap9000 {
		t.Fatal("preference not restored", c2.snapshot())
	}
}

func TestMacMTUCapPersistenceFailureKeepsPreviousValue(t *testing.T) {
	c := newLocalMacMTUCapController()
	c.configure(func(string) error { return errors.New("disk") }, func() (string, error) { return "1500", nil })
	c.masterChanged(true)
	waitMTUCap(t, c, "saved")
	if c.effective() != ncm.MTUCap1500 {
		t.Fatal("loaded value")
	}
	if err := c.set("9000", strings.Repeat("d", 32)); err != nil {
		t.Fatal(err)
	}
	s := waitMTUCap(t, c, "failed")
	if s.Error == "" || c.effective() != ncm.MTUCap1500 {
		t.Fatal("failed save must not change the effective cap", s)
	}
	bad := newLocalMacMTUCapController()
	bad.configure(nil, func() (string, error) { return "bogus", nil })
	bad.masterChanged(true)
	waitMTUCap(t, bad, "failed")
	if bad.effective() != ncm.MTUCapAuto {
		t.Fatal("corrupt preference must fall back to auto")
	}
}
