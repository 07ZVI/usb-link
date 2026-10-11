package usbhost

// Only unknown interrupted creation phases are eligible for early settlement.
// prepare supplies the unchanged protected old journal after conflict checks;
// finish is the existing complete reset-counter/native-absence settlement.
// attempted means selected for checking, never that settlement succeeded.
func settleInterruptedRecreate(t recreateTransaction, found bool, prepare func() ([]byte, error), finish func(recreateTransaction, []byte) error) (attempted bool, err error) {
	if !found || (t.State != "attempt" && t.State != "mapped") {
		return false, nil
	}
	old, err := prepare()
	if err != nil {
		return true, err
	}
	return true, finish(t, old)
}
