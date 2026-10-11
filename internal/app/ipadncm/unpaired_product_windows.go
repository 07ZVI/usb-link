//go:build windows && amd64

package ipadncm

// Retired protection metadata is read only by the one-time compatibility migration.
import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const unpairedProductOwnerFile = "network-only-usb-owner.json"

func readUnpairedProductOwner(dir string) (unpairedProductOwner, error) {
	if !networkOnlyDriverStoreProtected(dir) {
		return unpairedProductOwner{}, fmt.Errorf("UNPAIRED_PRODUCT_STORE_UNPROVEN")
	}
	b, e := readPortableProtectedFile(filepath.Join(dir, unpairedProductOwnerFile), 4096)
	if e != nil {
		return unpairedProductOwner{}, e
	}
	return decodeUnpairedProductOwner(b)
}
func readOwnedUnpairedProductChoice(dir string) (bool, error) {
	return readUnpairedProductChoiceWithDefault(dir, false)
}
func readUnpairedProductChoiceWithDefault(dir string, missingDefault bool) (bool, error) {
	b, e := readProtectedNetworkOnlyFile(filepath.Join(dir, "network-only-choice.json"), 65536)
	if os.IsNotExist(e) && missingDefault {
		return true, nil
	}
	if e != nil {
		return false, e
	}
	return decodeUnpairedProductChoice(b)
}

func unpairedProductReceiptRoots(r networkOnlyReceipt, o unpairedProductOwner) bool {
	if !o.valid() || (r.ServiceState != 1 && r.ServiceState != 4) || (r.StartType != 2 && r.StartType != 3) {
		return false
	}
	for _, n := range r.Nodes {
		if !validPortableReceipt(n) || !strings.EqualFold(n.Root, o.Root) {
			return false
		}
	}
	return true // A protected exact owner permits a service-only initial receipt.
}
