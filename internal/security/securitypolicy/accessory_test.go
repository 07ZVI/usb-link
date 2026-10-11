package securitypolicy

import "testing"

func TestAccessoryConsentPreservesExistingInputAndRequiresApprovalForNewUSB(t *testing.T) {
	p := AccessoryPolicy{Enabled: true}
	newUSB := AccessoryObservation{Complete: true, ExternalUSB: true}
	if d := p.Decide(newUSB); d.Permit || !d.Ask {
		t.Fatal(d)
	}
	existing := newUSB
	existing.ExistingAtActivation = true
	if d := p.Decide(existing); !d.Permit || d.Ask {
		t.Fatal(d)
	}
	existing.FunctionsChanged = true
	if d := p.Decide(existing); d.Permit || !d.Ask {
		t.Fatal("new HID function inherited existing-device permission", d)
	}
	newUSB.Accepted = true
	if d := p.Decide(newUSB); !d.Permit {
		t.Fatal(d)
	}
	p.AskEveryAttachment = true
	if d := p.Decide(newUSB); d.Permit || !d.Ask {
		t.Fatal(d)
	}
	newUSB.AttachmentApproved = true
	if d := p.Decide(newUSB); !d.Permit {
		t.Fatal(d)
	}
}

func TestInstallingSoftwareDoesNotEnableAccessoryBlocking(t *testing.T) {
	if d := (AccessoryPolicy{}).Decide(AccessoryObservation{}); !d.Permit || d.Ask {
		t.Fatal(d)
	}
	p := AccessoryPolicy{Enabled: true}
	if d := p.Decide(AccessoryObservation{Complete: true}); !d.Permit {
		t.Fatal("built-in/non-USB input blocked", d)
	}
	if d := p.Decide(AccessoryObservation{}); d.Permit {
		t.Fatal("incomplete scan admitted a new device", d)
	}
}

func TestActivationRequiresIndependentRecoveryAndWorkingInput(t *testing.T) {
	ok := ActivationReadiness{BaselineReviewed: true, CurrentInputVerified: true, RecoveryProvisioned: true, IndependentRecoveryVerified: true, ExecutorSupported: true}
	if !ok.CanActivate() {
		t.Fatal("ready activation rejected")
	}
	for _, field := range []string{"baseline", "input", "recovery", "independent", "support", "conflict"} {
		r := ok
		switch field {
		case "baseline":
			r.BaselineReviewed = false
		case "input":
			r.CurrentInputVerified = false
		case "recovery":
			r.RecoveryProvisioned = false
		case "independent":
			r.IndependentRecoveryVerified = false
		case "support":
			r.ExecutorSupported = false
		case "conflict":
			r.ConflictingPolicy = true
		}
		if r.CanActivate() {
			t.Fatal("unsafe activation", field)
		}
	}
}
