package ipadncm

// The legacy binary cannot read schema 2 even when Stopped is true. Remove only
// a completed metadata receipt; legacy ETL ownership records remain untouched.
func completeWPDTraceRecovery(j localWPDTraceJournal, inactive bool, write func(localWPDTraceJournal) error, remove func(localWPDTraceJournal) error) error {
	if !j.valid() || !inactive {
		return wpdTraceError("WPD_TRACE_STOP_UNCONFIRMED", 0)
	}
	if !j.Stopped {
		j.Stopped = true
		if err := write(j); err != nil {
			return err
		}
	}
	if j.Schema == 2 {
		return remove(j)
	}
	return nil
}

func wpdCompletedMetadataMatches(raw []byte, expected localWPDTraceJournal) bool {
	if !expected.valid() || expected.Schema != 2 || !expected.Stopped {
		return false
	}
	actual, err := decodeLocalWPDTraceJournal(raw)
	return err == nil && actual == expected
}
