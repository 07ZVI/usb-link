// Package usbgateway owns a default-deny application gate scoped to USB links.
package usbgateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Grant struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Decision string `json:"decision"`
}
type Request struct {
	ID        string `json:"id"`
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Protocol  string `json:"protocol"`
	Direction string `json:"direction"`
	Remote    string `json:"remote"`
}

func inspect(path string) (Grant, error) {
	if !filepath.IsAbs(path) || !strings.EqualFold(filepath.Ext(path), ".exe") || len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") {
		return Grant{}, fmt.Errorf("GATEWAY_APPLICATION_PATH_INVALID")
	}
	f, e := os.Open(path)
	if e != nil {
		return Grant{}, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > 1<<30 {
		return Grant{}, fmt.Errorf("GATEWAY_APPLICATION_INVALID")
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, 1<<30+1)); e != nil {
		return Grant{}, e
	}
	return Grant{Path: filepath.Clean(path), SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}
func validGrant(g Grant) bool {
	b, e := hex.DecodeString(g.SHA256)
	return e == nil && len(b) == 32 && (g.Decision == "allow" || g.Decision == "block") && filepath.IsAbs(g.Path)
}

// Session choices override saved choices. Each application receives exactly
// one decision, so revocation cannot leave a duplicate permit behind.
func effectiveGrants(saved []Grant, session map[string]Grant) []Grant {
	byPath := map[string]Grant{}
	for _, g := range saved {
		byPath[strings.ToLower(g.Path)] = g
	}
	for _, g := range session {
		byPath[strings.ToLower(g.Path)] = g
	}
	keys := []string{}
	for key := range byPath {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := []Grant{}
	for _, key := range keys {
		out = append(out, byPath[key])
	}
	return out
}
