package updater

import (
	"fmt"
	"io"
)

// Bounded diagnostic histories can exceed 64 KiB. Never silently truncate a
// status document: an oversized reply is an error, not a partial observation.
const controlResponseLimit = 1 << 20

func readControlResponse(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, controlResponseLimit+1))
	if err != nil {
		return nil, err
	}
	if len(b) > controlResponseLimit {
		return nil, fmt.Errorf("USB control response exceeds bounded limit")
	}
	return b, nil
}
