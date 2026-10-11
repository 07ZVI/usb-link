package latencyprobe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"suhang/usbnet/internal/transport/bridge"
	"suhang/usbnet/internal/transport/ncm"
	"testing"
	"time"
)

func packet(seq uint64, key, nonce []byte) []byte {
	p := make([]byte, 92)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], 92)
	p[8] = 64
	p[9] = 17
	copy(p[12:], ncm.MacIP[:])
	copy(p[16:], ncm.WindowsIP[:])
	binary.BigEndian.PutUint16(p[20:], 12345)
	binary.BigEndian.PutUint16(p[22:], 10691)
	binary.BigEndian.PutUint16(p[24:], 72)
	b := p[28:]
	copy(b, []byte("USBLRTT1"))
	copy(b[8:], nonce)
	binary.BigEndian.PutUint64(b[24:], seq)
	m := hmac.New(sha256.New, key)
	m.Write(b[:48])
	copy(b[48:], m.Sum(nil)[:16])
	binary.BigEndian.PutUint16(p[10:], ncm.Checksum(p[:20]))
	return p
}

func TestCompletionMarkerDoesNotRetainReusedBufferOrCrossSession(t *testing.T) {
	id := strings.Repeat("a", 32)
	key := strings.Repeat("b", 64)
	if err := Start(context.Background(), "BRIDGE", 120, id, key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Stop(id) })
	k, _ := hex.DecodeString(key)
	n, _ := hex.DecodeString(id)
	ip := packet(9, k, n)
	Mark(ip, true, "usb", time.Now())
	reply, _ := Receive(ip)
	frame := make([]byte, 14+len(reply))
	frame[12] = 8
	copy(frame[14:], reply)
	mark := CompletionMarker([][]byte{frame}, bridge.Peer{})
	if mark == nil {
		t.Fatal("valid reply not observed")
	}
	for i := range frame {
		frame[i] = 0
	}
	mark(time.Now())
	session := active.Load()
	session.Lock()
	observed := session.rows[9].USBObserved
	session.Unlock()
	if observed <= 0 {
		t.Fatal("copied identities lost on buffer reuse")
	}
	Stop(id)
	if err := Start(context.Background(), "BRIDGE", 120, id, key); err != nil {
		t.Fatal(err)
	}
	mark(time.Now())
	session = active.Load()
	session.Lock()
	observed = session.rows[9].USBObserved
	session.Unlock()
	if observed != 0 {
		t.Fatal("old observer stamped a replacement session")
	}
}
func TestNonceScopedEchoRejectsForgeryReplayAndFragments(t *testing.T) {
	id := strings.Repeat("a", 32)
	key := strings.Repeat("b", 64)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer Stop(id)
	if e := Start(ctx, "BRIDGE", 120, id, key); e != nil {
		t.Fatal(e)
	}
	k, _ := hex.DecodeString(key)
	n, _ := hex.DecodeString(id)
	p := packet(0, k, n)
	Mark(p, true, "usb", time.Now())
	reply, used := Receive(p)
	if !used || reply == nil || ncm.Checksum(reply[:20]) != 0 {
		t.Fatal("no valid echo")
	}
	if !hmac.Equal(reply[12:16], ncm.WindowsIP[:]) || binary.BigEndian.Uint16(reply[20:]) != 10691 {
		t.Fatal("wrong source")
	}
	if r, used := Receive(p); !used || r != nil {
		t.Fatal("replay echoed")
	}
	bad := packet(1, k, n)
	bad[91] ^= 1
	if _, used := Receive(bad); used {
		t.Fatal("forged payload accepted")
	}
	frag := packet(2, k, n)
	binary.BigEndian.PutUint16(frag[6:], 0x2000)
	frag[10], frag[11] = 0, 0
	binary.BigEndian.PutUint16(frag[10:], ncm.Checksum(frag[:20]))
	if _, used := Receive(frag); used {
		t.Fatal("fragment accepted")
	}
	if Stop(strings.Repeat("c", 32)) == nil {
		t.Fatal("wrong id stopped session")
	}
	if v, e := Result(id); e != nil || v == nil {
		t.Fatal(e)
	}
	if e := Stop(id); e != nil {
		t.Fatal(e)
	}
	if _, used := Receive(packet(3, k, n)); used {
		t.Fatal("stopped probe active")
	}
}
func TestProbeBoundsAndTemporaryStorage(t *testing.T) {
	id := strings.Repeat("a", 32)
	key := strings.Repeat("b", 64)
	for _, v := range []struct {
		k   string
		n   int
		key string
		ok  bool
	}{{"BRIDGE", 120, key, true}, {"BRIDGE", 121, key, false}, {"BRIDGE", 0, key, false}, {"APPLICATION", 30, key, true}, {"ICMP", 30, key, true}, {"RESULT", 0, "-", true}, {"STOP", 0, "-", true}, {"STOP", 1, "-", false}, {"BRIDGE", 30, "bad", false}, {"EXEC", 30, key, false}} {
		if (Validate(v.k, v.n, id, v.key) == nil) != v.ok {
			t.Fatal(v)
		}
	}
	if active.Load() != nil {
		t.Fatal("diagnostic storage resident without session")
	}
}
