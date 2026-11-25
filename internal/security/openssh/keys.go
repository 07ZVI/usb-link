// Package openssh manages Windows OpenSSH without owning its configuration.
package openssh

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

const MaxKeyFile = 128 << 10
const MaxImport = 16 << 10

// ID identifies the exact authorization line, including any restrictions.
// Fingerprint identifies key material, independent of comments/options.
type Key struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
	Comment     string `json:"comment"`
	Restricted  bool   `json:"restricted"`
}

func lineID(line []byte) string { h := sha256.Sum256(line); return hex.EncodeToString(h[:]) }
func keyLine(line []byte) (Key, bool) {
	p, comment, options, rest, err := ssh.ParseAuthorizedKey(bytes.TrimPrefix(line, []byte{0xef, 0xbb, 0xbf}))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 {
		return Key{}, false
	}
	comment = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, comment)
	runes := []rune(comment)
	if len(runes) > 48 {
		comment = string(runes[:48]) + "…"
	}
	return Key{lineID(line), p.Type(), ssh.FingerprintSHA256(p), comment, len(options) > 0}, true
}

func ListKeys(data []byte) ([]Key, error) {
	if len(data) > MaxKeyFile || !utf8.Valid(data) || bytes.ContainsRune(data, 0) {
		return nil, fmt.Errorf("公鑰檔案過大或不是 UTF-8 文字，請先手動檢查。")
	}
	keys := []Key{}
	seen := map[string]bool{}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if key, ok := keyLine(line); ok && !seen[key.ID] {
			keys = append(keys, key)
			seen[key.ID] = true
			if len(keys) > 64 {
				return nil, fmt.Errorf("此檔案超過 64 項公鑰，請先手動整理。")
			}
		}
	}
	return keys, nil
}

// Import validates the whole input before changing anything. Existing comments,
// unknown lines and options are preserved byte for byte. No private keys/options
// are accepted from a .pub import; existing restricted entries remain intact.
func Import(data []byte, input string) ([]byte, int, error) {
	keys, err := ListKeys(data)
	if err != nil {
		return nil, 0, err
	}
	if len(input) == 0 || len(input) > MaxImport || strings.Contains(input, "PRIVATE KEY") || !utf8.ValidString(input) {
		return nil, 0, fmt.Errorf("請提供 OpenSSH 格式的 .pub 公鑰，不能匯入私鑰。")
	}
	known := map[string]bool{}
	for _, k := range keys {
		known[k.Fingerprint] = true
	}
	var added []string
	valid := 0
	for _, line := range strings.Split(strings.TrimPrefix(input, "\ufeff"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, ok := keyLine([]byte(line))
		if !ok || key.Restricted {
			return nil, 0, fmt.Errorf("公鑰格式無效；每行應以 ssh-ed25519、ssh-rsa 或 ecdsa 等類型開頭。")
		}
		valid++
		if !known[key.Fingerprint] {
			added = append(added, line)
			known[key.Fingerprint] = true
		}
	}
	if valid == 0 {
		return nil, 0, fmt.Errorf("未找到有效的 OpenSSH 公鑰。")
	}
	if len(added) == 0 {
		return append([]byte(nil), data...), 0, nil
	}
	sep := "\n"
	if bytes.Contains(data, []byte("\r\n")) {
		sep = "\r\n"
	}
	out := append([]byte(nil), data...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, sep...)
	}
	out = append(out, strings.Join(added, sep)...)
	out = append(out, sep...)
	if _, err = ListKeys(out); err != nil {
		return nil, 0, err
	}
	return out, len(added), nil
}

func Delete(data []byte, id string) ([]byte, error) {
	if _, err := ListKeys(data); err != nil {
		return nil, err
	}
	if len(id) != 64 {
		return nil, fmt.Errorf("公鑰識別碼無效。")
	}
	parts := bytes.SplitAfter(data, []byte{'\n'})
	var out []byte
	found := false
	for _, part := range parts {
		line := bytes.TrimSuffix(bytes.TrimSuffix(part, []byte{'\n'}), []byte{'\r'})
		if key, ok := keyLine(line); ok && key.ID == id {
			found = true
			continue
		}
		out = append(out, part...)
	}
	if !found {
		return nil, fmt.Errorf("公鑰已變更或被移除，請重新整理後再試。")
	}
	return out, nil
}
