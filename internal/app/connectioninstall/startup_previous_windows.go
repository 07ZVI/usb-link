//go:build windows && amd64

package connectioninstall

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/platform/windows/wincom"
)

type startupSourceContextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r startupSourceContextReader) Read(b []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	return r.source.Read(b)
}

func readHistoricalStartupTask(ctx context.Context, root, name, sid string, allowMissing bool) (nativeStartupTask, bool, error) {
	var result nativeStartupTask
	needed := false
	expected := filepath.Join(root, canonicalPreviousStartupVersion, BinaryName)
	e := wincom.WithApartment(func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		scheduler, e := wincom.Create("{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}")
		if e != nil {
			return e
		}
		defer scheduler.Close()
		v, e := scheduler.Call("Connect")
		v.Clear()
		if e != nil {
			return e
		}
		folder, e := nativeObject(scheduler, "GetFolder", true, wincom.String("\\"))
		if e != nil {
			return e
		}
		defer folder.Close()
		tasks, e := nativeProductTasksVerified(folder, name, sid, func(command string) error {
			if allowMissing && strings.EqualFold(command, expected) {
				return nil
			}
			return Verify(command)
		}, !allowMissing)
		if e != nil {
			return e
		}
		for _, t := range tasks {
			if !strings.EqualFold(t.Command, expected) {
				continue
			}
			if len(tasks) != 1 || !nativeHistoricalTaskShape(t.XML) {
				return errors.New("STARTUP_PREVIOUS_TASK_SCOPE_CHANGED")
			}
			result = t
			needed = true
		}
		return ctx.Err()
	})
	return result, needed, e
}

func sameHistoricalStartupTask(a, b nativeStartupTask) bool {
	return a.Name == b.Name && a.Path == b.Path && a.XML == b.XML && a.Command == b.Command
}

// RestoreCanonicalPreviousStartupSource repairs only a missing fixed .97 task
// dependency using original publisher bytes embedded in the signed candidate.
// It does not execute the image, launch/register a task, fabricate a historical
// digest from a job pathname, replace a directory, or change unknown contents.
func RestoreCanonicalPreviousStartupSource(ctx context.Context, reader io.Reader) (restored bool, result error) {
	if ctx == nil || reader == nil {
		return false, errors.New("STARTUP_PREVIOUS_SOURCE_UNAVAILABLE")
	}
	installationCleanupMu.Lock()
	defer installationCleanupMu.Unlock()
	startupTaskLock.Lock()
	defer startupTaskLock.Unlock()
	unlock, e := coreLifecycleLock()
	if e != nil {
		return false, e
	}
	defer func() { result = errors.Join(result, unlock()) }()
	self, e := os.Executable()
	if e != nil {
		return false, e
	}
	binding, e := ActivateCoreOwner(self)
	if e != nil {
		return false, e
	}
	root, e := protectedRoot(false)
	if e != nil {
		return false, e
	}
	name, sid, e := nativeStartupDependencyIdentity()
	if e != nil {
		return false, e
	}
	dir := filepath.Join(root, canonicalPreviousStartupVersion)
	target := filepath.Join(dir, BinaryName)
	_, e = os.Lstat(dir)
	missing := os.IsNotExist(e)
	if e != nil && !missing {
		return false, e
	}
	if !missing {
		for _, item := range []struct {
			path      string
			directory bool
		}{{dir, true}, {target, false}, {filepath.Join(dir, "ownership.json"), false}} {
			if _, e = coreProtectedRead(item.path, item.directory, false); e != nil {
				return false, e
			}
		}
		if Verify(target) != nil {
			return false, errors.New("STARTUP_PREVIOUS_SOURCE_RESIDUAL_PRESERVED")
		}
		hash, e := fileHash(target)
		if e != nil || hash != canonicalPreviousStartupSHA {
			return false, errors.New("STARTUP_PREVIOUS_SOURCE_HASH_CHANGED")
		}
		return false, nil
	}
	first, needed, e := readHistoricalStartupTask(ctx, root, name, sid, true)
	if e != nil || !needed {
		return false, e
	}
	fresh := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		b, e := CurrentCoreBinding()
		if e != nil || b != binding {
			return errors.New("STARTUP_PREVIOUS_CORE_CHANGED")
		}
		if verified, e := protectedRoot(false); e != nil || verified != root {
			return errors.New("STARTUP_PREVIOUS_ROOT_CHANGED")
		}
		if _, e = os.Lstat(dir); !os.IsNotExist(e) {
			return errors.New("STARTUP_PREVIOUS_SOURCE_RESIDUAL_PRESERVED")
		}
		t, needed, e := readHistoricalStartupTask(ctx, root, name, sid, true)
		if e != nil || !needed || !sameHistoricalStartupTask(first, t) {
			return errors.New("STARTUP_PREVIOUS_TASK_CHANGED")
		}
		return nil
	}
	if e = fresh(); e != nil {
		return false, e
	}
	stage, e := os.MkdirTemp(root, "restore-task-source-")
	if e != nil {
		return false, e
	}
	stagingBinary := filepath.Join(stage, BinaryName)
	receiptPath := filepath.Join(stage, "ownership.json")
	defer func() { _ = os.Remove(stagingBinary); _ = os.Remove(receiptPath); _ = os.Remove(stage) }()
	if _, e = coreProtectedRead(stage, true, false); e != nil {
		return false, errors.New("STARTUP_PREVIOUS_STAGE_UNPROVEN")
	}
	f, e := os.OpenFile(stagingBinary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return false, e
	}
	e = copyCanonicalPreviousStartupSource(f, startupSourceContextReader{ctx, reader})
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return false, e
	}
	hash, e := fileHash(stagingBinary)
	if e != nil || hash != canonicalPreviousStartupSHA {
		return false, errors.New("STARTUP_PREVIOUS_SOURCE_HASH_CHANGED")
	}
	if _, e = coreProtectedRead(stagingBinary, false, false); e != nil {
		return false, e
	}
	b, e := json.Marshal(Receipt{ProductID, canonicalPreviousStartupVersion, canonicalPreviousStartupSHA})
	if e != nil {
		return false, e
	}
	r, e := os.OpenFile(receiptPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return false, e
	}
	_, e = r.Write(b)
	if e == nil {
		e = r.Sync()
	}
	e = errors.Join(e, r.Close())
	if e != nil {
		return false, e
	}
	if _, e = coreProtectedRead(receiptPath, false, true); e != nil {
		return false, e
	}
	if _, e = coreProtectedRead(stage, true, false); e != nil {
		return false, e
	}
	if e = fresh(); e != nil {
		return false, e
	}
	if e = windows.MoveFileEx(windows.StringToUTF16Ptr(stage), windows.StringToUTF16Ptr(dir), windows.MOVEFILE_WRITE_THROUGH); e != nil {
		return false, e
	}
	// Publication is atomic and write-through. On any post-publish ambiguity the
	// exact original receipt stays; no task mutation or false success follows.
	if _, e = coreProtectedRead(dir, true, false); e != nil {
		return false, e
	}
	if _, e = coreProtectedRead(filepath.Join(dir, "ownership.json"), false, true); e != nil {
		return false, e
	}
	if Verify(target) != nil {
		return false, errors.New("STARTUP_PREVIOUS_SOURCE_READBACK_FAILED")
	}
	if _, e = coreProtectedRead(target, false, false); e != nil {
		return false, e
	}
	got, e := fileHash(target)
	if e != nil || got != canonicalPreviousStartupSHA {
		return false, errors.New("STARTUP_PREVIOUS_SOURCE_READBACK_FAILED")
	}
	last, needed, e := readHistoricalStartupTask(ctx, root, name, sid, false)
	if e != nil || !needed || !sameHistoricalStartupTask(first, last) {
		return false, errors.New("STARTUP_PREVIOUS_TASK_CHANGED_AFTER_PUBLICATION")
	}
	current, e := CurrentCoreBinding()
	if e != nil || current != binding {
		return false, errors.New("STARTUP_PREVIOUS_CORE_CHANGED")
	}
	return true, nil
}
