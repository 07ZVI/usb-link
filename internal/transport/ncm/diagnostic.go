package ncm

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
)

const DiagnosticPort = 47771

var requestPattern = regexp.MustCompile(`^SUHANG-USB-PROBE/1 LOGS ([a-f0-9]{32})$`)

func DiagnosticRequest(f []byte) (string, [6]byte, bool) {
	var mac [6]byte
	e, err := ParseEthernet(f)
	if err != nil {
		return "", mac, false
	}
	b := e.Payload
	if e.Type != 0x800 || len(b) < 28 || b[0] != 0x45 || b[9] != 17 || be.Uint16(b[6:])&0x3fff != 0 {
		return "", mac, false
	}
	n := int(be.Uint16(b[2:]))
	if n < 28 || n > len(b) || Checksum(b[:20]) != 0 {
		return "", mac, false
	}
	b = b[:n]
	if !bytes.Equal(b[12:16], MacIP[:]) || !bytes.Equal(b[16:20], WindowsIP[:]) || be.Uint16(b[20:]) != DiagnosticPort || be.Uint16(b[22:]) != DiagnosticPort || int(be.Uint16(b[24:])) != n-20 {
		return "", mac, false
	}
	if be.Uint16(b[26:]) != 0 {
		pseudo := make([]byte, 12+n-20)
		copy(pseudo, b[12:20])
		pseudo[9] = 17
		be.PutUint16(pseudo[10:], uint16(n-20))
		copy(pseudo[12:], b[20:])
		if Checksum(pseudo) != 0 {
			return "", mac, false
		}
	}
	match := requestPattern.FindSubmatch(b[28:])
	if match == nil || e.Source[0]&1 != 0 || e.Source == [6]byte{} {
		return "", mac, false
	}
	return string(match[1]), e.Source, true
}
func DiagnosticFrames(content []byte, nonce string, mac [6]byte) ([][]byte, error) {
	if len(content) > 256*1024 || !requestPattern.MatchString("SUHANG-USB-PROBE/1 LOGS "+nonce) {
		return nil, fmt.Errorf("diagnostic bounds")
	}
	const chunk = 600
	count := (len(content) + chunk - 1) / chunk
	if count == 0 {
		count = 1
	}
	sum := sha256.Sum256(content)
	digest := hex.EncodeToString(sum[:])
	var out [][]byte
	for i := 0; i < count; i++ {
		part := content[min(i*chunk, len(content)):min((i+1)*chunk, len(content))]
		payload, err := json.Marshal(struct {
			Protocol string `json:"protocol"`
			Nonce    string `json:"nonce"`
			Index    int    `json:"index"`
			Total    int    `json:"total"`
			SHA      string `json:"sha256"`
			Data     string `json:"data"`
		}{"SUHANG-USB-PROBE/1", nonce, i, count, digest, base64.StdEncoding.EncodeToString(part)})
		if err != nil {
			return nil, err
		}
		b := make([]byte, 28+len(payload))
		b[0] = 0x45
		be.PutUint16(b[2:], uint16(len(b)))
		b[8] = 64
		b[9] = 17
		copy(b[12:], WindowsIP[:])
		copy(b[16:], MacIP[:])
		be.PutUint16(b[10:], Checksum(b[:20]))
		be.PutUint16(b[20:], DiagnosticPort)
		be.PutUint16(b[22:], DiagnosticPort)
		be.PutUint16(b[24:], uint16(len(b)-20))
		copy(b[28:], payload)
		pseudo := make([]byte, 12+len(b)-20)
		copy(pseudo, b[12:20])
		pseudo[9] = 17
		be.PutUint16(pseudo[10:], uint16(len(b)-20))
		copy(pseudo[12:], b[20:])
		check := Checksum(pseudo)
		if check == 0 {
			check = 65535
		}
		be.PutUint16(b[26:], check)
		out = append(out, Frame(mac, ProbeMAC, 0x800, b))
	}
	return out, nil
}
