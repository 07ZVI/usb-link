// Package setupwizard owns the interactive Windows installation flow.
package setupwizard

import "fmt"

type Page int

const (
	Welcome Page = iota
	License
	Components
	Ready
	Installing
	Finished
)

type Options struct {
	IPad     bool
	MacTools bool
}

// These are preparation choices, not blanket permission to replace device
// drivers. Device-specific binding retains the existing connection consent.
func (o Options) Dependencies() []string {
	ids := []string{"wintun", "dotnet"}
	if o.IPad {
		ids = append(ids, "apple-support", "apple-driver")
	}
	if o.MacTools {
		ids = append(ids, "zadig")
	}
	return ids
}

func (o Options) Summary(version, directory string) string {
	s := fmt.Sprintf("USB Link %s\r\n\r\n安装位置：%s\r\n\r\n必需组件\r\n• USB Link 程序与桌面界面\r\n• Wintun 网络驱动（已内置）\r\n• .NET 10 桌面运行库（已有则复用）", version, directory)
	if o.IPad {
		s += "\r\n\r\n已选择：iPad 通信组件与 USB 驱动包\r\n缺失时使用本地离线包或官方下载；Apple 安装向导会单独显示条款。"
	}
	if o.MacTools {
		s += "\r\n\r\n已选择：Mac USB 驱动准备工具\r\n仅准备经过验证的工具；连接时再确认目标设备。"
	}
	return s + "\r\n\r\n已有兼容组件不会重复安装。安装期间请保持此窗口打开。"
}

type Model struct {
	Page     Page
	Accepted bool
	Options  Options
}

func (m *Model) Next() bool {
	switch m.Page {
	case Welcome, Components:
		m.Page++
	case License:
		if !m.Accepted {
			return false
		}
		m.Page++
	case Ready:
		if !m.Accepted {
			return false
		}
		m.Page = Installing
	default:
		return false
	}
	return true
}

func (m *Model) Back() bool {
	if m.Page <= Welcome || m.Page >= Installing {
		return false
	}
	m.Page--
	return true
}
