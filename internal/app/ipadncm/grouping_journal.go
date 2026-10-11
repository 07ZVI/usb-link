package ipadncm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"suhang/usbnet/internal/diagnostics/grouptrial"
)

// Private exact original-value obligation, never serialized into public state.
type groupingJournal struct {
	Version        int    `json:"version"`
	RootID         string `json:"local_root_id"`
	DriverKey      string `json:"local_driver_key"`
	OriginalAbsent bool   `json:"original_value_absent"`
}

func validJournal(j groupingJournal) bool {
	return grouptrial.ValidRecoveryTarget(j.RootID, j.DriverKey, j.Version, j.OriginalAbsent)
}
func decodeGroupingJournal(b []byte) (j groupingJournal, err error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var tail any
	if len(b) > 1024 || d.Decode(&j) != nil || !validJournal(j) || d.Decode(&tail) != io.EOF {
		return j, fmt.Errorf("PRODUCT_GROUPING_PENDING_INVALID")
	}
	return j, nil
}
func productGroupingOwnerMatches(o unpairedProductOwner, j groupingJournal) bool {
	return o.valid() && validJournal(j) && strings.EqualFold(o.Root, j.RootID)
}
