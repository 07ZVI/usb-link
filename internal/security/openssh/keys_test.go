package openssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T, seed byte) string {
	t.Helper()
	p, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)).Public())
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(p)))
}

func TestImportValidatesAllInputAndDeduplicatesByMaterial(t *testing.T) {
	a, b := testKey(t, 1), testKey(t, 2)
	before := []byte("# keep this\r\nfrom=\"10.6.9.2\",no-port-forwarding " + a + " Mac\r\nunknown preserved line\r\n")
	out, n, err := Import(before, a+" different-comment\n"+b+" iPad\n"+b+" duplicate")
	if err != nil || n != 1 || !bytes.Equal(out, append(append([]byte(nil), before...), []byte(b+" iPad\r\n")...)) {
		t.Fatalf("import changed existing restrictions or did not deduplicate: %d %v", n, err)
	}
	for _, input := range []string{b + " valid\ninvalid", "-----BEGIN " + "OPENSSH PRIVATE KEY-----", "from=\"*\" " + b, "# only comments", "ssh-ed25519 invalid-base64", strings.Repeat("x", MaxImport+1)} {
		out, _, err := Import(before, input)
		if err == nil || out != nil {
			t.Fatal("invalid input partially applied", input[:min(40, len(input))])
		}
	}
}

func TestDeleteTargetsExactRestrictionLineAndPreservesBytes(t *testing.T) {
	a := testKey(t, 3)
	line1 := []byte("from=\"10.6.9.2\" " + a + " restricted")
	line2 := []byte(a + " unrestricted")
	data := append(append(append(append([]byte("# first\n"), line1...), []byte("\r\n# between\n")...), line2...), []byte("\n# last")...)
	keys, err := ListKeys(data)
	if err != nil || len(keys) != 2 || !keys[0].Restricted || keys[1].Restricted || keys[0].Fingerprint != keys[1].Fingerprint || keys[0].ID == keys[1].ID {
		t.Fatal(keys, err)
	}
	out, err := Delete(data, keys[0].ID)
	if err != nil || string(out) != "# first\n# between\n"+string(line2)+"\n# last" {
		t.Fatal(string(out), err)
	}
	if _, err = Delete(out, keys[0].ID); err == nil {
		t.Fatal("stale delete accepted")
	}
	p, _, _, _, _ := ssh.ParseAuthorizedKey(line2)
	digest := sha256.Sum256(p.Marshal())
	if keys[0].Fingerprint != "SHA256:"+base64.RawStdEncoding.EncodeToString(digest[:]) {
		t.Fatal("nonstandard fingerprint")
	}
}

func TestBOMOversizeAndInvalidEncoding(t *testing.T) {
	a := testKey(t, 4)
	existing := []byte("\ufeff" + a + " Mac\r\n")
	out, n, err := Import(existing, "\ufeff"+a+" other")
	if err != nil || n != 0 || !bytes.Equal(out, existing) {
		t.Fatal("BOM duplicate", n, err)
	}
	for _, data := range [][]byte{bytes.Repeat([]byte{'x'}, MaxKeyFile+1), {0xff}, {0}} {
		if _, err := ListKeys(data); err == nil {
			t.Fatal("unsafe existing file accepted")
		}
	}
}
