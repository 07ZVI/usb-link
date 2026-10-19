//go:build darwin && usblink_local_remote

package main

import (
	"net"
	"testing"
	"time"
)

func TestKernelReceiveTimestampSurvivesDelayedApplicationRead(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	udp, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	wrapped, err := timestamped(udp)
	if err != nil {
		t.Fatal(err)
	}
	wrapped.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = wrapped.Write([]byte("ready")); err != nil {
		t.Fatal(err)
	}
	server.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	_, peer, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	sent := time.Now()
	if _, err = server.WriteToUDP([]byte("reply"), peer); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	n, err := wrapped.Read(buf)
	arrival := time.Now()
	if err != nil || string(buf[:n]) != "reply" {
		t.Fatal(n, err)
	}
	kernel, valid := wrapped.(*timestampUDP).KernelReceived()
	if !valid || kernel.Before(sent.Add(-time.Millisecond)) || kernel.After(arrival) {
		t.Fatal(kernel, valid, sent, arrival)
	}
	if arrival.Sub(kernel) < 20*time.Millisecond {
		t.Fatal("application delay was folded into kernel timestamp", arrival.Sub(kernel))
	}
}
