//go:build !windows || !amd64

package main

import "fmt"

type observer struct{}

func newObserver(uint32) (*observer, error) {
	return nil, fmt.Errorf("usb-resource requires Windows; it does not measure the Mac host")
}
func (*observer) close() {}
func (*observer) capture(float64, float64) (sample, error) {
	return sample{}, fmt.Errorf("Windows required")
}
func (*observer) lifetimes() any { return nil }
func (*observer) starts() any    { return nil }
