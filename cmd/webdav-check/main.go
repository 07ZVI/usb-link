//go:build !windows

// Local compatibility fixture. It exposes only an explicitly supplied temporary
// test directory on loopback; never included in the Windows product.
package main

import (
	"flag"
	"log"
	"net/http"
	"suhang/usbnet/internal/sharing/fileshare"
)

func main() {
	dir := flag.String("dir", "", "temporary test directory")
	flag.Parse()
	if *dir == "" {
		log.Fatal("dir required")
	}
	state := &fileshare.State{}
	state.Enabled.Store(true)
	s, e := fileshare.New(*dir, "127.0.0.1", state, func() bool { return true })
	if e != nil {
		log.Fatal(e)
	}
	defer s.Close()
	log.Fatal(http.ListenAndServe("127.0.0.1:47775", s))
}
