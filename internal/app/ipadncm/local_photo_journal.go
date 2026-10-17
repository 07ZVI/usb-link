package ipadncm

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

const localPhotoJournalFile = "local-photo-isolation-v1.json"
const localPhotoJournalLimit = 65536

var localPhotoInstance = regexp.MustCompile(`(?i)^USB\\VID_05AC&PID_12AB(?:&REV_[0-9A-F]{4})?&MI_00\\[^\\\x00\r\n]+$`)

type localPhotoJournal struct {
	Schema  int                        `json:"schema"`
	Entries []portablePropertyOriginal `json:"entries"`
}

func localPhotoReceiptValid(n portableNodeReceipt) bool {
	return validPortableReceipt(n) && localPhotoInstance.MatchString(n.ID)
}
func (j localPhotoJournal) valid() bool {
	if j.Schema != 1 || len(j.Entries) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, p := range j.Entries {
		key := strings.ToUpper(p.Node.ID)
		if !p.valid() || !localPhotoReceiptValid(p.Node) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}
func decodeLocalPhotoJournal(b []byte) (localPhotoJournal, error) {
	var j localPhotoJournal
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if len(b) > localPhotoJournalLimit || d.Decode(&j) != nil || d.Decode(new(any)) != io.EOF || !j.valid() {
		return j, errors.New("PHOTO_JOURNAL_INVALID")
	}
	return j, nil
}
