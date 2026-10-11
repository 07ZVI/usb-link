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
	progress("正在检查现有安装…")
	cleanup, e := a.Check()
	if e != nil {
		return "", e
	}
	for _, id := range options.Dependencies() {
		if e := ctx.Err(); e != nil {
			return "", e
		}
		if e := a.Prepare(ctx, id); e != nil {
			return "", e
		}
	}
	if e := ctx.Err(); e != nil {
		return "", e
	}
	if cleanup {
		progress("正在备份并清理已删除程序的旧安装记录…")
		if e := a.Cleanup(ctx); e != nil {
			return "", e
		}
	}
	if e := ctx.Err(); e != nil {
		return "", e
	}
	progress("正在安装 USB Link…")
	return a.Install(ctx)
}
