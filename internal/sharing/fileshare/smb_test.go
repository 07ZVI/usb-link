package fileshare

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	smbclient "github.com/hirochachacha/go-smb2"
	"suhang/usbnet/internal/sharing/smbcore/vfs"
	"suhang/usbnet/internal/sharing/usbhttp"
)

func startSMBTest(t *testing.T) (*Server, *Catalog, string, func() (*smbclient.Session, net.Conn)) {
	t.Helper()
	dir := realTemp(t)
	c := NewCatalog(nil)
	if _, err := c.Add("", dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	state := &State{}
	state.Enabled.Store(true)
	s, err := NewMulti(c, "127.0.0.1", state, func() bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	probe.Close()
	stop, err := usbhttp.RegisterWithBinary(ctx, address, "127.0.0.1", http.NotFoundHandler(), s.ServeSMB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	connect := func() (*smbclient.Session, net.Conn) {
		conn, err := net.DialTimeout("tcp4", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		d := &smbclient.Dialer{Initiator: &smbclient.NTLMInitiator{User: "guest"}}
		session, err := d.Dial(conn)
		if err != nil {
			conn.Close()
			t.Fatal(err)
		}
		return session, conn
	}
	return s, c, filepath.Base(dir), connect
}

func TestSMBClientReadsWritesEnumeratesAndRenamesCatalog(t *testing.T) {
	_, c, name, connect := startSMBTest(t)
	session, conn := connect()
	defer conn.Close()
	defer session.Logoff()
	names, err := session.ListSharenames()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range names {
		if n == "USB" {
			found = true
		}
		if n == "USB Link" {
			t.Fatal("compatibility alias duplicated in discovery")
		}
	}
	if !found {
		t.Fatal("SMB USB share discovery empty")
	}
	old, err := session.Mount("USB Link")
	if err != nil {
		t.Fatal("old bookmark", err)
	}
	old.Umount()
	share, err := session.Mount("USB")
	if err != nil {
		t.Fatal(err)
	}
	defer share.Umount()
	rows, err := share.ReadDir(".")
	if err != nil || len(rows) != 1 || rows[0].Name() != name {
		t.Fatal(rows, err)
	}
	body := bytes.Repeat([]byte("USB 中文測試"), 16000)
	p := name + "/中文-測試.txt"
	if err := share.WriteFile(p, body, 0600); err != nil {
		t.Fatal("write", err)
	}
	actual, err := share.ReadFile(p)
	if err != nil || !bytes.Equal(actual, body) {
		t.Fatal("read integrity", len(actual), err)
	}
	if err := share.Rename(p, name+"/已重新命名.txt"); err != nil {
		t.Fatal("rename", err)
	}
	if err := share.Mkdir(name+"/目錄", 0755); err != nil {
		t.Fatal("mkdir", err)
	}
	stamp := time.Unix(1720000000, 0)
	if err := share.Chtimes(name+"/目錄", stamp, stamp); err != nil {
		t.Fatal("directory timestamps", err)
	}
	if st, err := share.Stat(name + "/目錄"); err != nil || !st.ModTime().Equal(stamp) {
		t.Fatal("directory timestamp integrity", st, err)
	}
	if err := share.Remove(name + "/已重新命名.txt"); err != nil {
		t.Fatal("remove", err)
	}
	if err := share.Remove(name); err == nil {
		t.Fatal("selected share root was deleted")
	}
	if _, err := os.Stat(c.List()[0].Path); err != nil {
		t.Fatal("local root missing", err)
	}
}

func TestSMBSharingRevocationClosesActiveConnection(t *testing.T) {
	s, _, _, connect := startSMBTest(t)
	_, conn := connect()
	defer conn.Close()
	s.State.Enabled.Store(false)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 4)
	_, err := conn.Read(b)
	if err == nil {
		t.Fatal("disabled share remains connected")
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("sharing revocation did not close idle connection")
	}
}

func TestSMBCatalogRejectsEscapesAndRevokesFolderHandles(t *testing.T) {
	s, c, name, _ := startSMBTest(t)
	b := &smbCatalog{s: s, ctx: context.Background()}
	for _, bad := range []string{name + "/../escape", name + "/file:stream", name + "/NUL", name + "/CON.txt", "C:\\Windows\\file"} {
		if _, _, err := b.resolve(bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	root := c.List()[0]
	if err := os.Symlink(outside, filepath.Join(root.Path, "link.txt")); err == nil {
		if f, err := b.Open(context.Background(), smbOpen(name+"/link.txt")); err == nil {
			f.Close(context.Background())
			t.Fatal("symlink escaped root")
		}
	}
	if err := os.Link(outside, filepath.Join(root.Path, "hardlink.txt")); err == nil {
		if f, err := b.Open(context.Background(), smbOpen(name+"/hardlink.txt")); err == nil {
			f.Close(context.Background())
			t.Fatal("hardlink accepted")
		}
	}
	if err := os.WriteFile(filepath.Join(root.Path, "existing.txt"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := b.Open(context.Background(), smbOpen(name+"/existing.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close(context.Background())
	if err := c.Remove(root.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Read(context.Background(), 0, make([]byte, 4)); !errors.Is(err, os.ErrPermission) {
		t.Fatal("revoked handle still reads", err)
	}
}

func smbOpen(p string) vfs.OpenOptions {
	return vfs.OpenOptions{Path: p, Disposition: vfs.DispositionOpen, DesiredAccess: 0x80000000}
}

func TestNativeMacSMBMountAndFileRoundTrip(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("requires native macOS SMB client")
	}
	_, _, _, connect := startSMBTest(t)
	session, conn := connect()
	address := conn.RemoteAddr().String()
	session.Logoff()
	conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	mount := realTemp(t)
	output, err := exec.CommandContext(ctx, "/sbin/mount_smbfs", "-N", "-o", "nobrowse,soft,nopassprompt,forcenewsession", "//guest:@"+address+"/USB", mount).CombinedOutput()
	if err != nil {
		t.Fatalf("native SMB mount: %v\n%s", err, output)
	}
	defer func() {
		out, err := exec.Command("/sbin/umount", mount).CombinedOutput()
		if err != nil {
			t.Errorf("unmount temporary SMB test: %v %s", err, out)
		}
	}()
	rows, err := os.ReadDir(mount)
	if err != nil || len(rows) != 1 {
		t.Fatal("native root listing", rows, err)
	}
	p := filepath.Join(mount, rows[0].Name(), "原生-中文-🌏.txt")
	body := bytes.Repeat([]byte("USB Link"), 40960)
	if err := os.WriteFile(p, body, 0600); err != nil {
		t.Fatal("native write", err)
	}
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("native integrity", len(got), err)
	}
	if err := os.Rename(p, p+".renamed"); err != nil {
		t.Fatal("native rename", err)
	}
	if err := os.Remove(p + ".renamed"); err != nil {
		t.Fatal("native remove", err)
	}
	d := filepath.Join(mount, rows[0].Name(), "目錄-原生時間")
	if err := os.Mkdir(d, 0755); err != nil {
		t.Fatal("native mkdir", err)
	}
	stamp := time.Unix(1720000000, 0)
	if err := os.Chtimes(d, stamp, stamp); err != nil {
		t.Fatal("native directory times", err)
	}
	if err := os.Remove(d); err != nil {
		t.Fatal("native rmdir", err)
	}
}

func TestSMBDirectoryPaginationAndAccountBoundary(t *testing.T) {
	_, c, name, connect := startSMBTest(t)
	for i := range 700 {
		if err := os.WriteFile(filepath.Join(c.List()[0].Path, fmt.Sprintf("中文-🌏-%04d.txt", i)), []byte("payload"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	session, conn := connect()
	defer conn.Close()
	defer session.Logoff()
	share, err := session.Mount("usb link")
	if err != nil {
		t.Fatal(err)
	}
	defer share.Umount()
	rows, err := share.ReadDir(name)
	if err != nil || len(rows) != 700 {
		t.Fatal("paginated catalog", len(rows), err)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.Name()] {
			t.Fatal("repeated entry", r.Name())
		}
		seen[r.Name()] = true
	}
	again, err := share.ReadDir(name)
	if err != nil || len(again) != 700 {
		t.Fatal("restart directory", len(again), err)
	}
	other, err := net.DialTimeout("tcp4", conn.RemoteAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.SetDeadline(time.Now().Add(time.Second))
	dialer := smbclient.Dialer{Initiator: &smbclient.NTLMInitiator{User: "Administrator", Password: "not-a-windows-credential"}}
	if session, err := dialer.Dial(other); err == nil {
		session.Logoff()
		t.Fatal("non-guest account accepted")
	}
}
