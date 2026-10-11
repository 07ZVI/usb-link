package ncm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestDiagnosticTransfer(t *testing.T) {
	nonce := strings.Repeat("a", 32)
	mac := [6]byte{2, 3, 4, 5, 6, 7}
	content := bytes.Repeat([]byte("日誌\n"), 500)
	frames, e := DiagnosticFrames(content, nonce, mac)
	if e != nil {
		t.Fatal(e)
	}
	var result []byte
	for i, f := range frames {
		eth, _ := ParseEthernet(f)
		b := eth.Payload
		n := int(be.Uint16(b[2:]))
		if eth.Destination != mac || len(f) > 1514 || Checksum(b[:20]) != 0 {
			t.Fatal("invalid response")
		}
		pseudo := make([]byte, 12+n-20)
		copy(pseudo, b[12:20])
		pseudo[9] = 17
		be.PutUint16(pseudo[10:], uint16(n-20))
		copy(pseudo[12:], b[20:n])
		if Checksum(pseudo) != 0 {
			t.Fatal("UDP checksum")
		}
		var msg struct {
			Index int    `json:"index"`
			Data  string `json:"data"`
		}
		if e = json.Unmarshal(b[28:n], &msg); e != nil || msg.Index != i {
			t.Fatal(e)
		}
		part, e := base64.StdEncoding.DecodeString(msg.Data)
		if e != nil {
			t.Fatal(e)
		}
		result = append(result, part...)
	}
	if !bytes.Equal(result, content) {
		t.Fatal("corrupt diagnostic transfer")
	}
	request := []byte("SUHANG-USB-PROBE/1 LOGS " + nonce)
	b := make([]byte, 28+len(request))
	b[0] = 0x45
	b[8] = 64
	b[9] = 17
	be.PutUint16(b[2:], uint16(len(b)))
	copy(b[12:], MacIP[:])
	copy(b[16:], WindowsIP[:])
	be.PutUint16(b[10:], Checksum(b[:20]))
	be.PutUint16(b[20:], DiagnosticPort)
	be.PutUint16(b[22:], DiagnosticPort)
	be.PutUint16(b[24:], uint16(len(b)-20))
	copy(b[28:], request)
	f := Frame(ProbeMAC, mac, 0x800, b)
	got, learned, ok := DiagnosticRequest(f)
	if !ok || got != nonce || learned != mac {
		t.Fatal("request rejected")
	}
	f[40] = 1
	if _, _, ok = DiagnosticRequest(f); ok {
		t.Fatal("invalid request accepted")
	}
}
