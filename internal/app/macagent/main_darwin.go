//go:build darwin

package macagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"suhang/usbnet/internal/diagnostics/logfile"
	"suhang/usbnet/internal/diagnostics/macalias"
	"suhang/usbnet/internal/transport/usbaddress"
	"syscall"
	"time"
)

const root = "/Library/Application Support/SuhangUSBNet"
const label = "app.suhang.usbnet.mac"
const plistPath = "/Library/LaunchDaemons/" + label + ".plist"
const product = "suhang-mac-alias-v1"
const binary = root + "/mac-usbnet"
const statePath = root + "/state.json"
const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>app.suhang.usbnet.mac</string>
<key>ProgramArguments</key><array><string>/Library/Application Support/SuhangUSBNet/mac-usbnet</string><string>--once</string></array>
<key>RunAtLoad</key><true/><key>StartInterval</key><integer>5</integer>
<key>ProcessType</key><string>Background</string>
<key>ExitTimeOut</key><integer>15</integer>
<key>WorkingDirectory</key><string>/Library/Application Support/SuhangUSBNet</string>
</dict></plist>
`

type State struct {
	Product, BinarySHA, LastStatus string
	AddressProfile                 string `json:"address_profile,omitempty"`
	Owned                          []macalias.Owned
}

func hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func run(path string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C"}
	b, e := cmd.CombinedOutput()
	if e != nil {
		return nil, fmt.Errorf("%s: %w: %s", path, e, boundedStatus(string(b)))
	}
	return b, nil
}
func inspect() ([]macalias.Interface, []macalias.Address, error) {
	b, e := run("/usr/sbin/ioreg", "-r", "-c", "AppleT8103USBXDCI", "-l", "-w0")
	if e != nil {
		return nil, nil, e
	}
	v, e := macalias.Parse(string(b))
	if e != nil {
		return nil, nil, e
	}
	b, e = run("/sbin/ifconfig", "-a")
	if e != nil {
		return nil, nil, e
	}
	return v, macalias.Addresses(string(b)), nil
}
func secure(path string, owned bool) error {
	path = filepath.Clean(path)
	for p := path; p != "/"; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if i.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink refused: %s", p)
		}
		if owned && p == path {
			s := i.Sys().(*syscall.Stat_t)
			if s.Uid != 0 || i.Mode().Perm()&0022 != 0 {
				return fmt.Errorf("untrusted permissions: %s", p)
			}
		}
	}
	return nil
}
func load() (State, error) {
	var s State
	if e := secure(root, true); e != nil {
		return s, e
	}
	if e := secure(statePath, true); e != nil {
		return s, e
	}
	f, e := os.Open(statePath)
	if e != nil {
		return s, e
	}
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	f.Close()
	if e != nil {
		return s, e
	}
	s, e = decodeState(b)
	if e != nil {
		return s, e
	}
	if s.Product != product {
		return s, fmt.Errorf("foreign state")
	}
	if e = secure(binary, true); e != nil {
		return s, e
	}
	b, e = os.ReadFile(binary)
	if e != nil {
		return s, e
	}
	if hash(b) != s.BinarySHA {
		return s, fmt.Errorf("binary hash changed")
	}
	return s, nil
}
func save(s State) error {
	s.LastStatus = boundedStatus(s.LastStatus)
	b, e := json.MarshalIndent(s, "", "  ")
	if e != nil {
		return e
	}
	p := statePath + ".tmp"
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer os.Remove(p)
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(p, statePath)
}
func lock() (*os.File, error) {
	p := root + "/lock"
	if e := secure(root, true); e != nil {
		return nil, e
	}
	fd, e := syscall.Open(p, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), p)
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func once() error {
	f, e := lock()
	if e != nil {
		return e
	}
	defer f.Close()
	s, e := load()
	if e != nil {
		return e
	}
	v, a, e := inspect()
	if e == nil {
		var p []macalias.Action
		p, e = addressPlan(v, a, s)
		if e == nil {

			for _, action := range p {
				if action.Add {
					found := false
					for _, o := range s.Owned {
						if o.Name == action.Interface {
							found = true
						}
					}
					if !found {
						for _, i := range v {
							if i.Name == action.Interface {
								s.Owned = append(s.Owned, macalias.Owned{Controller: i.Controller, Name: i.Name})
							}
						}
						if e = save(s); e != nil {
							return e
						}
					}
				}
				vv, aa, er := inspect()
				if er != nil {
					e = er
					break
				}
				pp, er := addressPlan(vv, aa, s)
				if er != nil {
					e = er
					break
				}
				allowed := false
				for _, x := range pp {
					if x == action {
						allowed = true
					}
				}
				if !allowed {
					e = fmt.Errorf("attachment changed; defer owned address update")
					break
				}
				if action.Add {
					_, e = run("/sbin/ifconfig", action.Interface, "inet", action.IP, "netmask", "255.255.255.0", "alias", "up")
				} else {
					_, e = run("/sbin/ifconfig", action.Interface, "inet", action.IP, "-alias")
				}
				if e != nil {
					break
				}
			}
			if e == nil {
				vv, aa, er := inspect()
				if er != nil {
					e = er
				} else if pp, er := addressPlan(vv, aa, s); er != nil {
					e = er
				} else if len(pp) != 0 {
					e = fmt.Errorf("owned address update pending")
				}
			}

		}
	}
	if e == nil && s.AddressProfile != usbaddress.Unified {
		s.AddressProfile = usbaddress.Unified
		e = save(s)
	}

	status := "READY_OR_WAITING"
	if e != nil {
		status = "WAITING: " + e.Error()
	}
	if status != s.LastStatus {
		if err := secure(root, true); err != nil {
			return err
		}
		w, err := logfile.Open(root+"/maintenance.log", 1024*1024)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "%s %s\n", time.Now().Format(time.RFC3339), status)
		w.Close()
		if err != nil {
			return err
		}
		s.LastStatus = status
		if err = save(s); err != nil {
			return err
		}
	}
	return e
}
func install(adopt string) error {
	if _, e := os.Lstat(root); e == nil {
		_, e = load()
		return errors.Join(fmt.Errorf("helper already exists; preserve installation"), e)
	} else if !os.IsNotExist(e) {
		return e
	}
	if _, e := os.Lstat(plistPath); !os.IsNotExist(e) {
		return fmt.Errorf("launchd path already exists or cannot be inspected")
	}
	if _, e := run("/bin/launchctl", "print", "system/"+label); e == nil {
		return fmt.Errorf("launchd label already in use; preserve existing job")
	}
	if e := secure(filepath.Dir(root), false); e != nil {
		return e
	}
	if e := secure(filepath.Dir(plistPath), false); e != nil {
		return e
	}
	v, a, e := inspect()
	if e != nil {
		return e
	}
	s := State{Product: product, AddressProfile: usbaddress.Unified}
	if adopt != "" {
		found := false
		for _, i := range v {
			if i.Name == adopt && i.Connected {
				s.Owned = []macalias.Owned{{Controller: i.Controller, Name: i.Name}}
				found = true
			}
		}
		if !found {
			return fmt.Errorf("adoption requires exact connected primary NCM")
		}
		exists := false
		for _, x := range a {
			if x.Interface == adopt && x.IP == "10.6.9.2" && x.Mask == "0xffffff00" {
				exists = true
			}
		}
		if !exists {
			return fmt.Errorf("owned alias missing during adoption")
		}
	}
	if _, e = addressPlan(v, a, s); e != nil {
		return e
	}
	self, e := os.Executable()
	if e != nil {
		return e
	}
	b, e := os.ReadFile(self)
	if e != nil {
		return e
	}
	s.BinarySHA = hash(b)
	if e = os.Mkdir(root, 0700); e != nil {
		return e
	}
	rollback := true
	defer func() {
		if rollback {
			run("/bin/launchctl", "bootout", "system/"+label)
			os.Remove(plistPath)
			for _, n := range []string{"mac-usbnet", "state.json", "state.json.tmp", "lock", "maintenance.log", "maintenance.log.1"} {
				os.Remove(filepath.Join(root, n))
			}
			os.Remove(root)
		}
	}()
	if e = os.WriteFile(binary, b, 0700); e != nil {
		return e
	}
	if e = save(s); e != nil {
		return e
	}
	// Existing addresses are preserved; in this session installation adopts only
	// the alias explicitly proved to belong to our earlier Mac setup.
	if e = os.WriteFile(plistPath, []byte(plist), 0644); e != nil {
		return e
	}
	if _, e = run("/bin/launchctl", "bootstrap", "system", plistPath); e != nil {
		return e
	}
	rollback = false
	return nil
}
func uninstall() error {
	s, e := load()
	if e != nil {
		return e
	}
	if e = secure(plistPath, true); e != nil {
		return e
	}
	b, e := os.ReadFile(plistPath)
	if e != nil {
		return e
	}
	if string(b) != plist {
		return fmt.Errorf("foreign launchd configuration")
	}
	entries, e := os.ReadDir(root)
	if e != nil {
		return e
	}
	known := map[string]bool{"mac-usbnet": true, "state.json": true, "lock": true, "maintenance.log": true, "maintenance.log.1": true}
	for _, x := range entries {
		if !known[x.Name()] || x.IsDir() {
			return fmt.Errorf("preserve unknown helper file: %s", x.Name())
		}
		if e = secure(filepath.Join(root, x.Name()), true); e != nil {
			return e
		}
	}
	if _, e = run("/bin/launchctl", "bootout", "system/"+label); e != nil { // An already unloaded, owned job is safe to retry.
		if _, err := run("/bin/launchctl", "print", "system/"+label); err == nil {
			return e
		}
	}
	f, e := lock()
	if e != nil {
		return e
	}
	defer f.Close()
	s, e = load()
	if e != nil {
		return e
	}
	v, a, e := inspect()
	if e != nil {
		return e
	}
	for j := range v {
		v[j].Connected = false
	}
	p, e := addressPlan(v, a, s)
	if e != nil {
		return e
	}
	for _, x := range p {
		if _, e = run("/sbin/ifconfig", x.Interface, "inet", x.IP, "-alias"); e != nil {
			return e
		}
	}
	if e = os.Remove(plistPath); e != nil {
		return e
	}
	for _, x := range entries {
		if e = os.Remove(filepath.Join(root, x.Name())); e != nil {
			return e
		}
	}
	return os.Remove(root)
}
func Main() {
	args := os.Args[1:]
	mode := "--status"
	if len(args) > 0 {
		mode = args[0]
	}
	var e error
	if mode == "--status" {
		v, a, err := inspect()
		e = err
		if e == nil {
			b, _ := json.MarshalIndent(struct {
				Interfaces []macalias.Interface
				Addresses  []macalias.Address
			}{v, filter(a, v)}, "", "  ")
			fmt.Println(string(b))
		}
	} else if os.Geteuid() != 0 {
		e = fmt.Errorf("administrator authorization required")
	} else {
		switch mode {
		case "--health":
			var s State
			s, e = load()
			if e == nil {
				b, _ := json.Marshal(struct{ Product, AddressProfile, BinarySHA, LastStatus string }{s.Product, s.AddressProfile, s.BinarySHA, s.LastStatus})
				fmt.Println(string(b))
			}
		case "--once":
			e = once()
		case "--upgrade":
			e = upgrade()
		case "--install":
			adopt := ""
			if len(args) == 3 && args[1] == "--adopt-interface" {
				adopt = args[2]
			} else if len(args) != 1 {
				e = fmt.Errorf("invalid install arguments")
				break
			}
			e = install(adopt)
		case "--uninstall":
			e = uninstall()
		default:
			e = fmt.Errorf("unknown operation")
		}
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func filter(a []macalias.Address, v []macalias.Interface) []macalias.Address {
	var out []macalias.Address
	for _, x := range a {
		for _, i := range v {
			if x.Interface == i.Name {
				out = append(out, x)
			}
		}
	}
	return out
}

func addressPlan(v []macalias.Interface, a []macalias.Address, s State) ([]macalias.Action, error) {
	if s.AddressProfile == "" || s.AddressProfile == usbaddress.Legacy {
		return macalias.MigrationPlan(v, a, s.Owned)
	}
	if s.AddressProfile != usbaddress.Unified {
		return nil, fmt.Errorf("unsupported owned address profile")
	}
	return macalias.PlanForProfile(v, a, s.Owned, usbaddress.Unified)
}
