package securitypolicy

// AccessoryPolicy describes a host-level consent gate for new external USB
// accessories, including keyboards, storage and composite devices. The default
// is a disabled policy; installing/upgrading USB Link does not activate it.
// Enforcement must happen before OS data/input delivery to count as protection.
type AccessoryPolicy struct {
	Enabled            bool
	AskEveryAttachment bool
}

type AccessoryObservation struct {
	Complete    bool
	ExternalUSB bool
	// Exact node/attachment baseline owned by the executor, not merely VID/PID.
	ExistingAtActivation bool
	FunctionsChanged     bool
	// Accepted matches the current instance AND function inventory. A USB Link
	// networking permission must not set this field for an OS input device.
	Accepted           bool
	AttachmentApproved bool
	Denied             bool // Explicit revocation overrides the baseline/remembered grant.
}

type AccessoryDecision struct {
	Permit bool
	Ask    bool
	Code   string
}

func (p AccessoryPolicy) Decide(v AccessoryObservation) AccessoryDecision {
	if !p.Enabled {
		return AccessoryDecision{Permit: true, Code: "USB_CONSENT_DISABLED"}
	}
	if !v.Complete {
		return AccessoryDecision{Code: "USB_CONSENT_INFORMATION_UNAVAILABLE"}
	}
	if !v.ExternalUSB {
		return AccessoryDecision{Permit: true, Code: "USB_CONSENT_OUTSIDE_EXTERNAL_SCOPE"}
	}
	if v.Denied {
		return AccessoryDecision{Code: "USB_DEVICE_PERMISSION_REVOKED"}
	}
	// Preserve a known working input path even in ask-every-attachment mode.
	// This is a bootstrap/recovery exception, not proof of device authenticity.
	if v.ExistingAtActivation && !v.FunctionsChanged {
		return AccessoryDecision{Permit: true, Code: "USB_EXISTING_DEVICE_PRESERVED"}
	}
	if v.AttachmentApproved && !v.FunctionsChanged {
		return AccessoryDecision{Permit: true, Code: "USB_ATTACHMENT_APPROVED"}
	}
	if v.Accepted && !p.AskEveryAttachment && !v.FunctionsChanged {
		return AccessoryDecision{Permit: true, Code: "USB_ACCEPTED_DEVICE_MATCHED"}
	}
	return AccessoryDecision{Ask: true, Code: "USB_LOCAL_APPROVAL_REQUIRED"}
}

// ActivationReadiness is separate from permission: no restrictive OS writes
// until recovery was actually provisioned and the current input path verified.
// Merely planning a rollback script is not RecoveryProvisioned.
type ActivationReadiness struct {
	BaselineReviewed            bool
	CurrentInputVerified        bool
	RecoveryProvisioned         bool
	IndependentRecoveryVerified bool
	ExecutorSupported           bool
	ConflictingPolicy           bool
}

func (r ActivationReadiness) CanActivate() bool {
	return r.BaselineReviewed && r.CurrentInputVerified && r.RecoveryProvisioned && r.IndependentRecoveryVerified && r.ExecutorSupported && !r.ConflictingPolicy
}
