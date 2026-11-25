//go:build windows && amd64

package openssh

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

//go:embed status.ps1
var statusScript string

type Account struct {
	SID  string `json:"sid"`
	Name string `json:"name"`
}
type Status struct {
	Installed bool      `json:"installed"`
	State     string    `json:"state"`
	StartMode string    `json:"start_mode"`
	Accounts  []Account `json:"accounts"`
	SID       string    `json:"sid"`
	Username  string    `json:"username"`
	Path      string    `json:"path"`
	Shared    bool      `json:"shared"`
	Keys      []Key     `json:"keys"`
}

// Data goes to stdin, never into PowerShell source or command interpolation.
func powershell(ctx context.Context, script string, input any) ([]byte, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	u := utf16.Encode([]rune(script))
	encoded := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(encoded[i*2:], v)
	}
	b, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	cmd.Stdin = bytes.NewReader(b)
	var output, stderr limitedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("OpenSSH 操作失敗：%s", strings.TrimSpace(stderr.String()))
	}
	if output.overflow {
		return nil, fmt.Errorf("OpenSSH 回覆過大。")
	}
	return output.Bytes(), nil
}

type limitedBuffer struct {
	bytes.Buffer
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remain := (256 << 10) - b.Len()
	if len(p) > remain {
		b.overflow = true
		p = p[:max(0, remain)]
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

var _ io.Writer = (*limitedBuffer)(nil)

func Query(ctx context.Context, action, sid string) (Status, error) {
	var s Status
	b, err := powershell(ctx, statusScript, map[string]string{"action": action, "sid": sid})
	if err != nil {
		return s, err
	}
	if err = json.Unmarshal(bytes.TrimPrefix(bytes.TrimSpace(b), []byte{0xef, 0xbb, 0xbf}), &s); err != nil {
		return s, fmt.Errorf("OpenSSH 狀態回覆無效。")
	}
	s.Keys = []Key{}
	if s.Path != "" {
		err = withKeyFile(s, false, func(data []byte, _ func([]byte) error) error { var e error; s.Keys, e = ListKeys(data); return e })
	}
	return s, err
}

func ChangeKeys(ctx context.Context, sid, input, id string) (Status, error) {
	if sid == "" {
		return Status{}, fmt.Errorf("請先選擇 Windows 帳戶。")
	}
	if id == "" {
		if _, _, err := Import(nil, input); err != nil {
			return Status{}, err
		}
	}
	s, err := Query(ctx, "refresh", sid)
	if err != nil {
		return s, err
	}
	if s.Path == "" || s.SID == "" {
		return s, fmt.Errorf("請先選擇 Windows 帳戶。")
	}
	err = withKeyFile(s, true, func(data []byte, save func([]byte) error) error {
		var out []byte
		var e error
		if id != "" {
			out, e = Delete(data, id)
		} else {
			out, _, e = Import(data, input)
		}
		if e != nil {
			return e
		}
		if bytes.Equal(data, out) {
			return nil
		}
		return save(out)
	})
	if err != nil {
		return s, err
	}
	return Query(ctx, "refresh", sid)
}
