package fileshare

import (
	"strings"
	"unicode/utf16"
)

// MS-FSA 2.1.4.4. Brackets and backslashes are literals, not shell glob syntax.
// Two bounded rows avoid recursive/backtracking expansion of wildcard input.
func smbMatchName(pattern, name string) bool {
	if pattern == "" || pattern == "*" || pattern == "*.*" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?<>\"") {
		return strings.EqualFold(pattern, name)
	}
	p := utf16.Encode([]rune(strings.ToUpper(pattern)))
	n := utf16.Encode([]rune(strings.ToUpper(name)))
	if len(p) > 255 || len(n) > 255 {
		return false
	}
	lastDot := -1
	for i, ch := range n {
		if ch == '.' {
			lastDot = i
		}
	}
	prev, next := make([]bool, len(n)+1), make([]bool, len(n)+1)
	prev[0] = true
	for _, ch := range p {
		clear(next)
		for j := range next {
			switch ch {
			case '*':
				next[j] = prev[j] || j > 0 && next[j-1]
			case '<': // DOS_STAR stops before the final period.
				next[j] = prev[j] || j > 0 && j != lastDot+1 && next[j-1]
			case '>': // DOS_QM can consume nothing at a period/end.
				next[j] = prev[j] && (j == len(n) || n[j] == '.') || j > 0 && n[j-1] != '.' && prev[j-1]
			case '"': // DOS_DOT consumes a period or nothing at end.
				next[j] = j == len(n) && prev[j] || j > 0 && n[j-1] == '.' && prev[j-1]
			case '?':
				next[j] = j > 0 && prev[j-1]
			default:
				next[j] = j > 0 && prev[j-1] && n[j-1] == ch
			}
		}
		prev, next = next, prev
	}
	return prev[len(n)]
}
