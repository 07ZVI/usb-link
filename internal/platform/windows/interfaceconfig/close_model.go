package interfaceconfig

// Recovery uses its original-value verifier even after a preceding step has
// removed a Ready condition. Ordinary close must never call persistence restore.
func runSecondaryClose(requested bool, normalVerify, restorePersistent, restoreDAD func() error) error {
	if requested {
		if e := restorePersistent(); e != nil {
			return e
		}
	} else {
		if e := normalVerify(); e != nil {
			return e
		}
	}
	return restoreDAD()
}
