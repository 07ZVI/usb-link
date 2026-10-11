package connectioninstall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strings"
)

// Exact published source supplied inside the signed repair release. These are
// not caller-selectable versions, paths or digests, and the image is never run.
const canonicalPreviousStartupVersion = "0.8.97"
const canonicalPreviousStartupSHA = "643a6a38ce2d31d767f85bc6691736dbd8d15fea9c5556247874fc3ea6da9123"
const canonicalPreviousStartupBytes int64 = 105738240

func copyCanonicalPreviousStartupSource(dst io.Writer, src io.Reader) error {
	if src == nil || dst == nil {
		return errors.New("STARTUP_PREVIOUS_SOURCE_UNAVAILABLE")
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(dst, h), io.LimitReader(src, canonicalPreviousStartupBytes+1))
	if e != nil {
		return e
	}
	if n != canonicalPreviousStartupBytes || hex.EncodeToString(h.Sum(nil)) != canonicalPreviousStartupSHA {
		return errors.New("STARTUP_PREVIOUS_SOURCE_HASH_CHANGED")
	}
	return nil
}

// Query failures retain every prior executable, including disabled-task targets.
func startupDependencyRetentionReason(commands []string, target string, queryError error) string {
	if queryError != nil {
		return "startup task dependency unverified"
	}
	for _, command := range commands {
		if strings.EqualFold(filepath.Clean(command), filepath.Clean(target)) {
			return "owned startup task still references this version"
		}
	}
	return ""
}
