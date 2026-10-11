package usbaddress

import "fmt"

const Legacy = "legacy"
const Unified = "unified"

type Addresses struct{ Windows, Peer, Subnet string }

func Lookup(profile string) (Addresses, error) {
	switch profile {
	case Legacy:
		return Addresses{"10.77.0.2", "10.77.0.1", "10.77.0.0/24"}, nil
	case Unified:
		return Addresses{"10.6.9.1", "10.6.9.2", "10.6.9.0/24"}, nil
	default:
		return Addresses{}, fmt.Errorf("unsupported USB address profile")
	}
}
