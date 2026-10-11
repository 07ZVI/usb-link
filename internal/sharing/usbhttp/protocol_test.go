package usbhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestBinaryCapacityKeepsHTTPAvailableAndClosesOnDetach(t *testing.T) {
	address := endpoint(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	accepted := make(chan struct{}, 4)
	stop, err := RegisterWithBinary(ctx, address, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "HTTP maintenance available") }), func(ctx context.Context, c net.Conn) {
		var b [4]byte
		io.ReadFull(c, b[:])
		accepted <- struct{}{}
		<-ctx.Done()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	peers := []net.Conn{}
	for range 4 {
		conn, err := net.DialTimeout("tcp4", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		peers = append(peers, conn)
		conn.Write([]byte{0, 0, 0, 0})
		select {
		case <-accepted:
		case <-time.After(time.Second):
			t.Fatal("binary prefix lost")
		}
	}
	extra, err := net.DialTimeout("tcp4", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.Write([]byte{0, 0, 0, 0})
	extra.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("binary cap exceeded")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("excess binary session not closed")
	}
	response, err := client("127.0.0.1").Get("http://" + address + "/maintenance/connection")
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(content) != "HTTP maintenance available" {
		t.Fatal("binary sessions blocked HTTP", err)
	}
	stop()
	for _, conn := range peers {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err := conn.Read(make([]byte, 1))
		if err == nil {
			t.Fatal("detached binary session remains open")
		}
	}
}
