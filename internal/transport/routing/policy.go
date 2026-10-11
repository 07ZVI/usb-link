// Package routing defines the opt-in IPv4 Internet boundary shared by the core
// and bridge worker. It contains no native configuration or application logic.
package routing

import (
	"net/netip"
	"time"
)

type Lease struct {
	Schema   int      `json:"schema"`
	Epoch    string   `json:"epoch"`
	Root     string   `json:"root"`
	Expires  int64    `json:"expires"`
	Excluded []string `json:"excluded"`
	Enabled  bool     `json:"enabled"`
}
type Observation struct {
	Epoch    string `json:"epoch"`
	DHCPACK  bool   `json:"dhcp_ack"`
	Outbound bool   `json:"outbound"`
	Inbound  bool   `json:"inbound"`
}

var Reserved = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"}

func Public(a netip.Addr, excluded []string) bool {
	if !a.Is4() {
		return false
	}
	for _, s := range append(append([]string{}, Reserved...), excluded...) {
		p, e := netip.ParsePrefix(s)
		if e != nil || !p.Addr().Is4() {
			return false
		}
		if p.Contains(a) {
			return false
		}
	}
	return true
}
func (l Lease) Valid(root string, now time.Time) bool {
	return l.Schema == 1 && l.Enabled && len(l.Epoch) == 32 && root != "" && l.Root == root && l.Expires > now.Unix() && l.Expires <= now.Add(10*time.Second).Unix()
}
func (l Lease) Allow(a netip.Addr, root string, now time.Time) bool {
	return l.Valid(root, now) && Public(a, l.Excluded)
}

// PublicPrefixes computes the exact complement, including upstream on-link
// networks even when they use publicly allocated addresses.
func PublicPrefixes(excluded []string) []netip.Prefix {
	out := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	for _, s := range append(append([]string{}, Reserved...), excluded...) {
		block, e := netip.ParsePrefix(s)
		if e != nil || !block.Addr().Is4() {
			return nil
		}
		next := []netip.Prefix{}
		for _, p := range out {
			next = append(next, subtract(p, block.Masked())...)
		}
		out = next
	}
	return out
}
func subtract(p, b netip.Prefix) []netip.Prefix {
	if !p.Overlaps(b) {
		return []netip.Prefix{p}
	}
	if b.Bits() <= p.Bits() {
		return nil
	}
	left := netip.PrefixFrom(p.Addr(), p.Bits()+1)
	a := p.Addr().As4()
	bit := p.Bits()
	a[bit/8] |= 1 << uint(7-bit%8)
	right := netip.PrefixFrom(netip.AddrFrom4(a), p.Bits()+1)
	return append(subtract(left, b), subtract(right, b)...)
}

// PublicPrefix rejects a mask that includes any reserved or on-link address.
func PublicPrefix(p netip.Prefix, excluded []string) bool {
	if !p.IsValid() || !p.Addr().Is4() {
		return false
	}
	for _, s := range append(append([]string{}, Reserved...), excluded...) {
		b, e := netip.ParsePrefix(s)
		if e != nil || !b.Addr().Is4() || p.Overlaps(b) {
			return false
		}
	}
	return true
}
