package ipadncm

import (
	"regexp"
	"sort"
	"strings"
)

var netDriverKeyPattern = regexp.MustCompile(`(?i)^\{4D36E972-E325-11CE-BFC1-08002BE10318\}\\[0-9]{4}$`)
var netGUIDPattern = regexp.MustCompile(`(?i)^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$`)

// A healthy devnode alone cannot select a network interface: require the
// instance's Net class key and its valid NetCfgInstanceId as well.
func canonicalNetworkBinding(started bool, key, guid string) (string, bool) {
	if !started || !netDriverKeyPattern.MatchString(key) || !netGUIDPattern.MatchString(guid) || guid == "{00000000-0000-0000-0000-000000000000}" {
		return "", false
	}
	return strings.ToLower(guid), true
}

// Counter changes are evidence of passive interface activity only. Never
// compare replaced/restarted adapters or infer IP/Moonlight from these bytes.
func passiveCounterDelta(previousKey, currentKey string, previousIn, previousOut, currentIn, currentOut uint64) (in, out uint64, valid bool) {
	if previousKey == "" || previousKey != currentKey || currentIn < previousIn || currentOut < previousOut {
		return 0, 0, false
	}
	return currentIn - previousIn, currentOut - previousOut, true
}

// Cached location paths preserve physical-position checks during a session.
// Empty, duplicate or changed observations fail closed; order/case can vary.
func sameCachedLocation(before, current []string) bool {
	if len(before) == 0 || len(before) != len(current) || len(before) > 16 {
		return false
	}
	normalize := func(v []string) ([]string, bool) {
		x := make([]string, len(v))
		for i, p := range v {
			if p == "" || len(p) > 4096 {
				return nil, false
			}
			x[i] = strings.ToUpper(p)
		}
		sort.Strings(x)
		for i := 1; i < len(x); i++ {
			if x[i] == x[i-1] {
				return nil, false
			}
		}
		return x, true
	}
	a, ok := normalize(before)
	if !ok {
		return false
	}
	b, ok := normalize(current)
	if !ok {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
