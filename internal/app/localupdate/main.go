//go:build usblink_local_remote

package localupdate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
	"time"
)

func Main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func readFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("regular input file required")
	}
	return readBounded(f, limit)
}

func initKey(path string, output io.Writer) error {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString(hex.EncodeToString(private) + "\n")
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	_, err = fmt.Fprintln(output, hex.EncodeToString(public))
	return err
}

func sign(keyPath, executable, version, output string) error {
	b, err := readFile(keyPath, 4096)
	if err != nil {
		return err
	}
	k, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid signing key")
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(k[:32]), k) || !bytes.Equal(k[32:], remoteupdate.PublisherKey()) {
		return fmt.Errorf("key does not match publisher")
	}
	f, err := os.Open(executable)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, remoteupdate.MaxBinary+1))
	if err != nil {
		return err
	}
	m := remoteupdate.Manifest{Product: remoteupdate.Product, Version: version, Bytes: n,
		SHA256: hex.EncodeToString(h.Sum(nil)), Expires: time.Now().Add(7 * 24 * time.Hour).Unix()}
	m.Sign(k)
	if err = m.Verify(remoteupdate.PublisherKey(), "0.0.0", time.Now()); err != nil {
		return err
	}
	b, err = json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	// A typo must not overwrite the private key or installer with the manifest.
	out, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := out.Write(append(b, '\n'))
	closeErr := out.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func validID(id string) bool { return len(id) == 32 && strings.Trim(id, "0123456789abcdef") == "" }

func cancelStaged(ctx context.Context, c *client, status []byte, output io.Writer) error {
	var before struct {
		Update struct {
			ID, Status string
			Retry      string `json:"persistence_retry"`
			RetryID    string `json:"retry_job_id"`
		} `json:"update"`
	}
	if json.Unmarshal(status, &before) != nil {
		return fmt.Errorf("invalid staged update status")
	}
	u := before.Update
	retry := u.Status == "persistence_recovery_required" && u.Retry == "true" && u.RetryID == u.ID
	if !validID(u.ID) || u.Status != "staged" && u.Status != "awaiting_local_admin" && !retry {
		return fmt.Errorf("only the current idle staged update can be cancelled")
	}
	body, _ := json.Marshal(map[string]string{"id": u.ID})
	b, err := c.request(ctx, "POST", "/v1/cancel", bytes.NewReader(body), "", 0)
	if err != nil {
		return err
	}
	var ack struct{ ID, Status string }
	if json.Unmarshal(b, &ack) != nil || ack.ID != u.ID || ack.Status != "cancelled" && ack.Status != "persistence_recovered" {
		return fmt.Errorf("staged update cancellation not confirmed")
	}
	_, err = fmt.Fprintln(output, "Exact staged update cancellation confirmed:", u.ID)
	return err
}

func upload(ctx context.Context, c *client, manifestPath, executable, current string, stageOnly bool, output io.Writer) error {
	b, err := readFile(manifestPath, 4096)
	if err != nil {
		return err
	}
	m, err := remoteupdate.Decode(b)
	if err != nil {
		return err
	}
	if err = m.Verify(remoteupdate.PublisherKey(), current, time.Now()); err != nil {
		return err
	}
	f, err := os.Open(executable)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = remoteupdate.VerifyBinary(f, m); err != nil {
		return err
	}
	if _, err = f.Seek(0, 0); err != nil {
		return err
	}
	prepared, err := c.request(ctx, "POST", "/v1/prepare", f, base64.StdEncoding.EncodeToString(b), m.Bytes)
	if err != nil {
		return err
	}
	var staged struct {
		ID      string `json:"id"`
		Version string `json:"version"`
		Status  string `json:"status"`
	}
	if json.Unmarshal(prepared, &staged) != nil || !validID(staged.ID) || staged.Version != m.Version || staged.Status != "verified" {
		return fmt.Errorf("invalid staging acknowledgement; installation not requested")
	}
	if stageOnly {
		_, err = fmt.Fprintln(output, "Signed update staged; installation not requested:", staged.ID)
		return err
	}
	body, _ := json.Marshal(map[string]string{"id": staged.ID})
	ack, err := c.request(ctx, "POST", "/v1/apply", bytes.NewReader(body), "", 0)
	if err != nil {
		return err
	}
	var pending struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if json.Unmarshal(ack, &pending) != nil || pending.ID != staged.ID || pending.Status != "installation_pending" {
		return fmt.Errorf("installation acknowledgement not confirmed; inspect Windows status")
	}
	_, err = fmt.Fprintln(output, "Installation requested:", staged.ID, "Check the Windows interface for approval and completion. This acknowledgement does not confirm installation; USB availability after restart follows the installed developer debug setting.")
	return err
}

func run(args []string, output io.Writer) error {
	fs := flag.NewFlagSet("usb-link-local-update", flag.ContinueOnError)
	init := fs.String("init-key", "", "create a new private key file with mode 0600; print only its public key")
	key := fs.String("sign-key", "", "local publisher Ed25519 private key; sign only, never transmitted")
	version := fs.String("version", "", "new release version when signing")
	exe := fs.String("exe", "", "Windows installer file")
	manifest := fs.String("manifest", "", "signed manifest input, or new output file when signing")
	connection := fs.String("connection", "", "private connection JSON; default discovers over USB")
	status := fs.Bool("status", false, "read status only")
	cancelUpdate := fs.Bool("cancel", false, "cancel only the current authenticated idle staged update")
	stageOnly := fs.Bool("stage-only", false, "stage signed bytes without requesting installation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *init != "" {
		if fs.NFlag() != 1 {
			return fmt.Errorf("init-key must be used alone")
		}
		return initKey(*init, output)
	}
	if *key != "" {
		if *status || *cancelUpdate || *stageOnly || *connection != "" || *version == "" || *exe == "" || *manifest == "" {
			return fmt.Errorf("signing requires only sign-key, version, exe and manifest")
		}
		return sign(*key, *exe, *version, *manifest)
	}
	if *version != "" || *status && *cancelUpdate || (*status || *cancelUpdate) && (*stageOnly || *exe != "" || *manifest != "") || !*status && !*cancelUpdate && (*exe == "" || *manifest == "") {
		return fmt.Errorf("choose status, cancel, or a signed manifest and installer")
	}
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("USB network actions require macOS; key creation and signing are available on this platform")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	var data []byte
	var err error
	if *connection != "" {
		data, err = readFile(*connection, 4096)
	} else {
		data, err = discover(ctx)
	}
	if err != nil {
		return err
	}
	inv, err := decodeInvitation(data)
	if err != nil {
		return err
	}
	c, closeClient := newClient(inv)
	defer closeClient()
	b, err := c.request(ctx, "GET", "/v1/status", nil, "", 0)
	if err != nil {
		return err
	}
	var before struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(b, &before) != nil || !remoteupdate.Newer(before.Version, "0.0.0") {
		return fmt.Errorf("invalid Windows version status")
	}
	if *status {
		_, err = fmt.Fprintln(output, string(b))
		return err
	}
	if *cancelUpdate {
		return cancelStaged(ctx, c, b, output)
	}
	return upload(ctx, c, *manifest, *exe, before.Version, *stageOnly, output)
}
