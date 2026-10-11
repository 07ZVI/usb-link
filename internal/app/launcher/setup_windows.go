//go:build windows && amd64

package launcher

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/app/setupwizard"
	"suhang/usbnet/internal/dependencies"
	"sync/atomic"
	"time"
)

func runSetupWizard(ctx context.Context) {
	root, err := connectioninstall.Root()
	if err != nil {
		dialog("无法读取安装位置。\n"+err.Error(), 0x10)
		return
	}
	terms, err := payload.ReadFile("assets/setup-license.txt")
	if err != nil {
		dialog("无法读取许可条款，安装尚未开始。", 0x10)
		return
	}
	installed, open, err := setupwizard.Run(ctx, setupwizard.Config{
		Version:   version,
		Directory: filepath.Join(root, connectioninstall.CurrentApplicationDirectory),
		License:   "USB Link 使用 GPL-3.0-only 与官方 Wintun DLL 链接例外。\r\nWintun 使用随包附带的官方预编译二进制许可。\r\nApple 等外部组件须在各自官方安装向导中单独同意条款。\r\n\r\n" + string(terms),
		Work: func(work context.Context, options setupwizard.Options, progress func(string)) (string, error) {
			progress("正在检查现有安装…")
			if err := connectioninstall.PreflightLocalInstallationForSetup(version); err != nil {
				return "", err
			}
			var preparing atomic.Bool
			preparing.Store(true)
			unsubscribe := dependencies.Default.ObserveProgress(func(s dependencies.Status) {
				if !preparing.Load() {
					return
				}
				name := map[string]string{"wintun": "网络驱动 Wintun", "dotnet": ".NET 桌面运行库", "apple-support": "Apple 通信组件", "apple-driver": "iPad USB 驱动包", "zadig": "Mac USB 驱动工具"}[s.ID]
				state := map[string]string{"detecting": "检查已有组件", "downloading": "下载官方组件", "installing": "准备组件", "ready": "已就绪", "failed": "未完成", "cancelled": "已取消"}[s.State]
				text := fmt.Sprintf("%s · %s", name, state)
				if s.Total > 0 {
					text += fmt.Sprintf("\r\n%.1f / %.1f MB", float64(s.Bytes)/(1<<20), float64(s.Total)/(1<<20))
				}
				progress(text)
			})
			defer unsubscribe()
			for _, id := range options.Dependencies() {
				if err := work.Err(); err != nil {
					return "", err
				}
				if _, err := dependencies.Ensure(work, id); err != nil {
					return "", err
				}
			}
			preparing.Store(false)
			progress("正在安装 USB Link…")
			phaseCtx, stopPhases := context.WithCancel(work)
			phasesDone := make(chan struct{})
			go func() {
				defer close(phasesDone)
				timer := time.NewTicker(250 * time.Millisecond)
				defer timer.Stop()
				for {
					select {
					case <-phaseCtx.Done():
						return
					case <-timer.C:
						progress(connectioninstall.InstallationProgressText())
					}
				}
			}()
			installed, err := installBundledRelease(work)
			stopPhases()
			<-phasesDone
			return installed, err
		},
	})
	if err != nil {
		dialog("安装向导无法打开，安装尚未开始。\n"+err.Error(), 0x10)
		return
	}
	if open && installed != "" {
		child := exec.Command(installed)
		if err := child.Start(); err != nil {
			dialog("程序已安装，无法打开界面。\n"+err.Error(), 0x10)
		} else {
			_ = child.Process.Release()
		}
	}
}
