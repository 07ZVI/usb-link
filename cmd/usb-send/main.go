// usb-send is a Mac-side data sender for the already authorized USB link.
// The Windows receiver never executes the received file.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"suhang/usbnet/internal/sharing/filedrop"
	"time"
)

func send(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > filedrop.MaxBytes {
		return fmt.Errorf("file must be regular and at most 512 MiB")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, filedrop.MaxBytes+1))
	if e != nil || n != st.Size() {
		return fmt.Errorf("file changed while hashing")
	}
	sha := hex.EncodeToString(h.Sum(nil))
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	q, e := http.NewRequestWithContext(ctx, "POST", "http://10.6.9.1:10690/upload", f)
	if e != nil {
		return e
	}
	q.ContentLength = st.Size()
	q.Header.Set("X-Suhang-Filename", filepath.Base(path))
	q.Header.Set("X-Suhang-SHA256", sha)
	d := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("10.6.9.2")}}
	transport := &http.Transport{DialContext: d.DialContext, Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	c := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("receiver redirect refused") }}
	r, e := c.Do(q)
	if e != nil {
		return e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("USB receiver status %d", r.StatusCode)
	}
	var receipt filedrop.Receipt
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || receipt.Bytes != n || receipt.SHA256 != sha {
		return fmt.Errorf("receiver receipt does not match local file")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return fmt.Errorf("unexpected receiver response")
	}
	fmt.Printf("Received and SHA256 verified: %d bytes, %s\n", n, sha)
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: suhang-usb-send FILE")
		os.Exit(2)
	}
	if e := send(os.Args[1]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
