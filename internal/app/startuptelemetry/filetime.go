package startuptelemetry

import "time"

func filetimeAnchor(ticks uint64, now time.Time) (time.Time, bool) {
	const epoch uint64 = 116444736000000000
	if ticks < epoch {
		return time.Time{}, false
	}
	v := ticks - epoch
	seconds := v / 10000000
	if seconds > uint64(now.Add(time.Second).Unix()) {
		return time.Time{}, false
	}
	at := time.Unix(int64(seconds), int64(v%10000000)*100).UTC()
	return at, !at.After(now.Add(time.Second))
}
