package connectioninstall

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
)

var preparedUserPattern = regexp.MustCompile(`^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$`)

func validPreparedUserSID(s string) bool { return preparedUserPattern.MatchString(s) }

// Manual continuation cannot downgrade or borrow another user's service binding.
func preparedInstallPolicy(next, previous, userSID, ownerSID string, bound, sameSource bool) bool {
	if !validPreparedUserSID(userSID) {
		return false
	}
	if !bound {
		return true
	}
	return userSID == ownerSID && !sameSource && remoteupdate.Newer(next, previous)
}
func preparedJobIdle(status string, candidatePID uint32, candidateCreation uint64, candidateSource string) bool {
	switch status {
	case "complete", "declined", "cancelled":
		return true
	case "failed":
		return candidatePID == 0 && candidateCreation == 0 && candidateSource == ""
	}
	return false
}

func preparedJournalUnique(b []byte) bool {
	if len(b) == 0 || len(b) > 32768 {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func(int) bool
	walk = func(depth int) bool {
		if depth > 16 {
			return false
		}
		t, e := d.Token()
		if e != nil {
			return false
		}
		if x, ok := t.(json.Delim); ok {
			switch x {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					s, ok := k.(string)
					s = strings.ToLower(s)
					if e != nil || !ok || seen[s] {
						return false
					}
					seen[s] = true
					if !walk(depth + 1) {
						return false
					}
				}
				last, e := d.Token()
				return e == nil && last == json.Delim('}')
			case '[':
				for d.More() {
					if !walk(depth + 1) {
						return false
					}
				}
				last, e := d.Token()
				return e == nil && last == json.Delim(']')
			default:
				return false
			}
		}
		return true
	}
	return walk(0) && d.Decode(new(any)) == io.EOF
}
