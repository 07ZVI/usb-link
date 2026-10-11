package interfaceconfig

import (
	"errors"
	"testing"
)

func TestSecondaryCloseSeparatesReadyProofFromOriginalRecovery(t *testing.T) {
	for _, x := range []struct {
		name                               string
		requested, normalFail, restoreFail bool
		wantVerify, wantRestore, wantDAD   int
	}{{"normal", false, false, false, 1, 0, 1}, {"normal changed", false, true, false, 1, 0, 0}, {"partial prior original restoration", true, true, false, 0, 1, 1}, {"unknown original", true, false, true, 0, 1, 0}} {
		t.Run(x.name, func(t *testing.T) {
			nv, np, nd := 0, 0, 0
			e := runSecondaryClose(x.requested, func() error {
				nv++
				if x.normalFail {
					return errors.New("not ready")
				}
				return nil
			}, func() error {
				np++
				if x.restoreFail {
					return errors.New("original unproven")
				}
				return nil
			}, func() error { nd++; return nil })
			if nv != x.wantVerify || np != x.wantRestore || nd != x.wantDAD {
				t.Fatal(nv, np, nd, e)
			}
			if nd == 0 && e == nil {
				t.Fatal("failure erased")
			}
		})
	}
}
