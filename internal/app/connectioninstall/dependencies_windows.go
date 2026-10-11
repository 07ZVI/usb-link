//go:build windows && amd64

package connectioninstall

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func DependencyDirectory() (string, error) {
	root, e := protectedRoot(true)
	if e != nil {
		return "", e
	}
	return protectedRootAt(filepath.Join(root, "dependencies"), true)
}
func VerifyDependencyPath(path string) error {
	root, e := DependencyDirectory()
	if e != nil {
		return e
	}
	rel, e := filepath.Rel(root, path)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("DEPENDENCY_OUTSIDE_OWNED_ROOT")
	}
	for p := path; p != root; p = filepath.Dir(p) {
		if noReparse(p) != nil {
			return fmt.Errorf("DEPENDENCY_PATH_REDIRECTED")
		}
	}
	return nil
}

// Only the marked private dependency tree belongs to this product. System-wide
// Apple software, installed drivers and shared runtimes are never removed here.
func RemoveDependencies() error {
	dir, e := DependencyDirectory()
	if e != nil {
		return e
	}
	if _, e = os.Stat(filepath.Join(dir, "internet-journal.json")); e == nil {
		return fmt.Errorf("DEPENDENCY_GATEWAY_RECOVERY_PENDING")
	}
	if e = filepath.WalkDir(dir, func(path string, de os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return VerifyDependencyPath(path)
	}); e != nil {
		return e
	}
	return os.RemoveAll(dir)
}
