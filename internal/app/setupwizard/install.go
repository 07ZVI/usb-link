package setupwizard

import (
	"context"
	"fmt"
)

// InstallationActions keep preparation and legacy cleanup separate. A read-only
// match cannot authorize removal before every selected component is ready.
type InstallationActions struct {
	Check    func() (bool, error)
	Prepare  func(context.Context, string) error
	Cleanup  func(context.Context) error
	Install  func(context.Context) (string, error)
	Progress func(string)
	Record   func(stage, state string, err error)
}

func Install(ctx context.Context, options Options, a InstallationActions) (string, error) {
	if a.Check == nil || a.Prepare == nil || a.Cleanup == nil || a.Install == nil {
		return "", fmt.Errorf("SETUP_ACTIONS_REQUIRED")
	}
	progress := func(s string) {
		if a.Progress != nil {
			a.Progress(s)
		}
	}
	if e := ctx.Err(); e != nil {
		return "", e
	}
	record := func(stage, state string, err error) {
		if a.Record != nil {
			a.Record(stage, state, err)
		}
	}
	progress("正在检查现有安装…")
	record("preflight", "started", nil)
	cleanup, e := a.Check()
	if e != nil {
		record("preflight", "failed", e)
	} else {
		record("preflight", "passed", nil)
	}
	if e != nil {
		return "", e
	}
	for _, id := range options.Dependencies() {
		if e := ctx.Err(); e != nil {
			return "", e
		}
		record("component:"+id, "started", nil)
		if e := a.Prepare(ctx, id); e != nil {
			record("component:"+id, "failed", e)
			return "", e
		}
		record("component:"+id, "passed", nil)
	}
	if e := ctx.Err(); e != nil {
		return "", e
	}
	if cleanup {
		progress("正在备份并清理已删除程序的旧安装记录…")
		record("legacyCleanup", "started", nil)
		if e := a.Cleanup(ctx); e != nil {
			record("legacyCleanup", "failed", e)
			return "", e
		}
		record("legacyCleanup", "passed", nil)
	}
	if e := ctx.Err(); e != nil {
		return "", e
	}
	progress("正在安装 USB Link…")
	record("install", "started", nil)
	path, err := a.Install(ctx)
	if err != nil {
		record("install", "failed", err)
	} else {
		record("install", "passed", nil)
	}
	return path, err
}
