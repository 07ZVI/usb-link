//go:build windows && amd64 && usblink_offline_components

// Private offline installer. Not part of the public USB Link build.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"suhang/usbnet/internal/app/connectioninstall"
	"suhang/usbnet/internal/dependencies"
	"suhang/usbnet/scripts/windows-offline-components/pipeline"
)

type offlineTransport struct{}

func (offlineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("OFFLINE_KIT: network download disabled; restore the verified local package")
}
func check(a dependencies.Asset, p string) error {
	st, e := os.Lstat(p)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() || st.Size() > a.MaxBytes {
		return errors.New("invalid package type/size")
	}
	var h hash.Hash
	switch a.Algorithm {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		return errors.New("unknown checksum")
	}
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	if _, e = io.Copy(h, io.LimitReader(f, a.MaxBytes+1)); e != nil {
		return e
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), a.Digest) {
		return fmt.Errorf("checksum mismatch: %s", a.ID)
	}
	return nil
}
func packagePath(base string, a dependencies.Asset) string {
	u, _ := url.Parse(a.URL)
	return filepath.Join(base, filepath.Base(u.Path))
}
func stage(base, root string, a dependencies.Asset) error {
	u, e := url.Parse(a.URL)
	if e != nil {
		return e
	}
	dest := filepath.Join(root, a.ID+"-"+a.Version+"-"+a.Digest[:16]+filepath.Ext(u.Path))
	if _, e = os.Lstat(dest); e == nil {
		if e = connectioninstall.VerifyDependencyPath(dest); e != nil {
			return e
		}
		return check(a, dest) // Refuse to replace a damaged or unrelated existing file.
	} else if !os.IsNotExist(e) {
		return e
	}
	src, e := os.Open(packagePath(base, a))
	if e != nil {
		return e
	}
	defer src.Close()
	tmp, e := os.CreateTemp(root, "offline-stage-")
	if e != nil {
		return e
	}
	defer os.Remove(tmp.Name())
	_, e = io.Copy(tmp, io.LimitReader(src, a.MaxBytes+1))
	ce := tmp.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = check(a, tmp.Name()); e != nil {
		return e
	}
	if e = connectioninstall.VerifyDependencyPath(tmp.Name()); e != nil {
		return e
	}
	sourceName, e := windows.UTF16PtrFromString(tmp.Name())
	if e != nil {
		return e
	}
	targetName, e := windows.UTF16PtrFromString(dest)
	if e != nil {
		return e
	}
	// Never replace a concurrently staged file. Only an independently checked
	// exact catalog package can satisfy the race.
	if e = windows.MoveFileEx(sourceName, targetName, windows.MOVEFILE_WRITE_THROUGH); e != nil {
		if connectioninstall.VerifyDependencyPath(dest) == nil && check(a, dest) == nil {
			return nil
		}
		return e
	}
	return nil
}

var bundleVersion string

func run() error {
	packageDir := flag.String("package-dir", "", "Flat directory containing the original official component packages")
	reportPath := flag.String("report", "", "Result report outside the component folder")
	verifyOnly := flag.Bool("verify-only", false, "Verify the offline packages without preparing components")
	flag.Parse()
	if flag.NArg() != 0 || *packageDir == "" || !filepath.IsAbs(*packageDir) {
		return errors.New("请双击 install_all.bat，不要单独运行安装助手")
	}
	if !*verifyOnly && !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("请允许 Windows 管理员权限提示")
	}
	ids := []string{"dotnet", "wintun", "zadig", "apple-driver", "apple-support"}
	names := map[string]string{"dotnet": ".NET Runtime", "wintun": "Wintun 网络组件", "zadig": "Zadig 驱动工具", "apple-driver": "Apple USB 驱动", "apple-support": "Apple 通信组件"}
	var components []pipeline.Component
	assets := map[string]dependencies.Asset{}
	for _, id := range ids {
		a, e := dependencies.Lookup(id)
		if e != nil {
			return e
		}
		assets[id] = a
		components = append(components, pipeline.Component{ID: id, Name: names[id], Version: a.Version})
	}
	dependencies.Configure(connectioninstall.DependencyDirectory, connectioninstall.VerifyDependencyPath)
	dependencies.Default.Client = &http.Client{Transport: offlineTransport{}}
	verifier := &dependencies.WindowsPlatform{}
	root := ""
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	r := pipeline.Run(ctx, components, pipeline.Actions{
		Verify: func(ctx context.Context, c pipeline.Component) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			a := assets[c.ID]
			fmt.Printf("校验：%s %s\n", c.Name, c.Version)
			p := packagePath(*packageDir, a)
			if e := check(a, p); e != nil {
				return fmt.Errorf("%s 文件校验失败：%w", c.Name, e)
			}
			if e := verifier.Verify(a, p); e != nil {
				return fmt.Errorf("%s 官方签名校验失败：%w", c.Name, e)
			}
			return nil
		},
		Detect: func(_ context.Context, c pipeline.Component) (bool, error) {
			if root == "" {
				var e error
				root, e = connectioninstall.DependencyDirectory()
				if e != nil {
					return false, e
				}
			}
			_, ready := dependencies.Default.Platform.Detect(assets[c.ID], root)
			if ready {
				fmt.Printf("跳过：%s 已有效安装／准备\n", c.Name)
			}
			return ready, nil
		},
		Prepare: func(ctx context.Context, c pipeline.Component) error {
			a := assets[c.ID]
			fmt.Printf("准备：%s %s\n", c.Name, c.Version)
			if c.ID == "apple-support" {
				fmt.Println("即将打开 Apple 官方安装向导，请按向导完成；不会强制重启。")
			}
			if e := stage(*packageDir, root, a); e != nil {
				return fmt.Errorf("%s 缓存准备失败：%w", c.Name, e)
			}
			_, e := dependencies.Ensure(ctx, c.ID)
			if e != nil && strings.Contains(e.Error(), "DEPENDENCY_REBOOT_REQUIRED") {
				return pipeline.ErrRebootRequired
			}
			return e
		},
	}, *verifyOnly)
	fmt.Println("\n组件结果：")
	labels := map[string]string{"verified": "文件已验证", "reused": "已有组件，已跳过", "ready": "已准备完成", "failed": "失败", "not-run": "未执行", "reboot-required": "需重启后完成"}
	for _, c := range r.Components {
		fmt.Printf("  %s：%s\n", c.Name, labels[c.State])
		if c.Problem != "" {
			fmt.Println("    " + c.Problem)
		}
	}
	if *reportPath != "" {
		report := struct {
			pipeline.Report
			BundleVersion    string `json:"bundle_version"`
			NetworkDownloads bool   `json:"network_downloads"`
		}{Report: r, BundleVersion: bundleVersion}
		data, e := json.MarshalIndent(report, "", "  ")
		if e != nil {
			return e
		}
		if e = os.WriteFile(*reportPath, append(data, '\n'), 0600); e != nil {
			return fmt.Errorf("无法保存结果日志：%w", e)
		}
	}
	if r.Outcome == "failed" {
		return errors.New("组件准备未全部完成；已完成的组件会在下次运行时复用")
	}
	if r.RebootRequired {
		return pipeline.ErrRebootRequired
	}
	if *verifyOnly {
		fmt.Println("校验完成，未安装任何组件。")
	} else {
		fmt.Println("\n组件准备完成。接下来安装／启动 USB Link 并连接设备。")
		fmt.Println("USB 接口绑定由 USB Link 按实际设备处理；本脚本不会更换键鼠等其他设备的驱动。")
	}
	return nil
}
func main() {
	if e := run(); errors.Is(e, pipeline.ErrRebootRequired) {
		fmt.Println("\n请重启 Windows，然后再次运行 install_all.bat 核对状态。")
		os.Exit(3010)
	} else if e != nil {
		fmt.Fprintln(os.Stderr, "未完成：", e)
		os.Exit(1)
	}
}
