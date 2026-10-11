// Developer-side USB-only release publisher and update client.
package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"suhang/usbnet/internal/app/remoteupdate"
	"suhang/usbnet/internal/diagnostics/rawusb"
	"suhang/usbnet/internal/transport/usbrecovery"
	"suhang/usbnet/internal/transport/usbroute"
	"time"
)

func Main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	keyFile := flag.String("sign-key", "", "local Ed25519 private key file; never transmitted")
	ver := flag.String("version", "", "release version when signing")
	binary := flag.String("exe", "", "Windows installer path")
	manifestFile := flag.String("manifest", "", "signed manifest input/output path")
	invitation := flag.String("connection", "", "optional private connection JSON; default discovers over USB")
	recoveryTest := flag.Bool("recovery-test", false, "request a bounded 45-second Windows recovery self-test")
	forceRecovery := flag.Bool("recovery", false, "use the independent USB recovery transport")
	perfNonce := flag.String("profile-nonce", "", "existing public resource job id; never a credential")
	perfKind := flag.String("profile", "", "fixed bridge diagnostic: CPU, TRACE, ALLOCS, HEAP, GC100 or GC800")
	perfSeconds := flag.Int("profile-seconds", 0, "bounded capture duration")
	perfOutput := flag.String("profile-output", "", "local capture file")
	perfSpeed := flag.String("profile-speed-client", "", "optional local native speed client for timed capture")
	statusOnly := flag.Bool("status", false, "read status only")
	cancelUpdate := flag.Bool("cancel-update", false, "cancel only the current authenticated idle staged update")
	stageOnly := flag.Bool("stage-only", false, "verify and stage signed bytes without applying; developer experiment")
	flag.Parse()
	if *cancelUpdate && (*stageOnly || *statusOnly || *recoveryTest || *perfKind != "" || *keyFile != "" || *binary != "") {
		return fmt.Errorf("cancel-update must be used alone")
	}
	if *stageOnly && (*statusOnly || *recoveryTest || *perfKind != "" || *keyFile != "") {
		return fmt.Errorf("stage-only requires a signed installer and no other action")
	}
	if *keyFile != "" {
		b, e := os.ReadFile(*keyFile)
		if e != nil {
			return e
		}
		k, e := hex.DecodeString(strings.TrimSpace(string(b)))
		if e != nil || len(k) != ed25519.PrivateKeySize {
			return fmt.Errorf("invalid signing key")
		}
		if !ed25519.PublicKey(k[32:]).Equal(remoteupdate.PublisherKey()) {
			return fmt.Errorf("key does not match publisher")
		}
		f, e := os.Open(*binary)
		if e != nil {
			return e
		}
		defer f.Close()
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(f, remoteupdate.MaxBinary+1))
		if e != nil {
			return e
		}
		m := remoteupdate.Manifest{Product: remoteupdate.Product, Version: *ver, Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil)), Expires: time.Now().Add(7 * 24 * time.Hour).Unix()}
		m.Sign(k)
		if e = m.Verify(remoteupdate.PublisherKey(), "0.0.0", time.Now()); e != nil {
			return e
		}
		b, _ = json.MarshalIndent(m, "", "  ")
		return os.WriteFile(*manifestFile, append(b, '\n'), 0644)
	}
	var inv struct {
		URLs  []string `json:"urls"`
		Pin   string   `json:"certificate_sha256"`
		Token string   `json:"token"`
	}
	var b []byte
	var recoveryClient *usbrecovery.Client
	var e error
	if *invitation != "" {
		b, e = os.ReadFile(*invitation)
	} else {
		if !*forceRecovery {
			b, e = discoverUSB()
		}
		if *forceRecovery || e != nil {
			discoverCtx, done := context.WithTimeout(context.Background(), 25*time.Second)
			b, recoveryClient, e = usbrecovery.Discover(discoverCtx)
			done()
		}
	}
	if recoveryClient != nil {
		defer recoveryClient.Close()
	}
	if e != nil {
		return e
	}
	if json.Unmarshal(b, &inv) != nil || len(inv.URLs) != 1 || inv.URLs[0] != "https://10.6.9.1:47775" || len(inv.Token) != 64 {
		return fmt.Errorf("USB-only invitation required")
	}
	pin, e := hex.DecodeString(inv.Pin)
	if e != nil || len(pin) != 32 {
		return fmt.Errorf("invalid certificate pin")
	}
	dialer := &net.Dialer{Control: usbroute.Control, Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("10.6.9.2")}}
	dial := dialer.DialContext
	if recoveryClient != nil {
		dial = recoveryClient.DialContext
	}
	tr := &http.Transport{Proxy: nil, MaxConnsPerHost: 1, DialContext: dial, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, VerifyConnection: func(c tls.ConnectionState) error {
		if len(c.PeerCertificates) == 0 {
			return fmt.Errorf("server certificate missing")
		}
		sum := sha256.Sum256(c.PeerCertificates[0].Raw)
		if hex.EncodeToString(sum[:]) != inv.Pin {
			return fmt.Errorf("Windows identity changed")
		}
		return nil
	}}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect refused") }}
	// Only read-only status polling may move from raw recovery to the normal
	// USB socket. Both transports retain the same TLS identity and USB source.
	var normalStatusClient *http.Client
	if recoveryClient != nil {
		normalTransport := tr.Clone()
		normalTransport.DialContext = dialer.DialContext
		defer normalTransport.CloseIdleConnections()
		normalStatusClient = &http.Client{Transport: normalTransport, Timeout: 10 * time.Second, CheckRedirect: client.CheckRedirect}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	request := func(method, path string, body io.Reader, header string, length int64) ([]byte, error) {
		if method == "GET" && path == "/v1/status" && body == nil && header == "" {
			return readUSBStatus(ctx, client, normalStatusClient, inv.URLs[0]+path, inv.Token)
		}
		q, e := http.NewRequestWithContext(ctx, method, inv.URLs[0]+path, body)
		if e != nil {
			return nil, e
		}
		q.Header.Set("Authorization", "Bearer "+inv.Token)
		if header != "" {
			q.Header.Set("X-Suhang-Release", header)
			q.ContentLength = length
		}
		r, e := client.Do(q)
		if e != nil {
			return nil, e
		}
		defer r.Body.Close()
		b, e := readControlResponse(r.Body)
		if e != nil {
			return nil, e
		}
		if r.StatusCode/100 != 2 {
			return nil, fmt.Errorf("server %d: %s", r.StatusCode, b)
		}
		return b, nil
	}
	b, e = request("GET", "/v1/status", nil, "", 0)
	if e != nil {
		return e
	}
	if *perfKind != "" {
		if _, _, _, raw := rawusb.Command(*perfKind); raw {
			return collectRaw(ctx, client, inv.URLs[0], inv.Token, *perfKind, *perfSeconds, *perfOutput)
		}
		return collectPerformance(ctx, client, inv.URLs[0], inv.Token, *perfKind, *perfSeconds, *perfOutput, *perfSpeed, *perfNonce)
	}
	if *statusOnly {
		fmt.Println(string(b))
		return nil
	}
	if *cancelUpdate {
		payload, id, err := ownedCancellationPayload(b)
		if err != nil {
			return err
		}
		ack, err := request("POST", "/v1/cancel", strings.NewReader(string(payload)), "", 0)
		if err != nil {
			return err
		}
		if err = verifyCancellationAck(ack, id); err != nil {
			return err
		}
		fmt.Println("Exact idle update cancellation/persistence recovery confirmed; recovery receipts and signed bytes retained.")
		return nil
	}
	if *recoveryTest {
		b, e = request("POST", "/v1/recovery-test", nil, "", 0)
		if e != nil {
			return e
		}
		fmt.Println(string(b))
		return nil
	}
	var before struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(b, &before) != nil {
		return fmt.Errorf("invalid status")
	}
	b, e = os.ReadFile(*manifestFile)
	if e != nil {
		return e
	}
	m, e := remoteupdate.Decode(b)
	if e != nil {
		return e
	}
	if e = m.Verify(remoteupdate.PublisherKey(), before.Version, time.Now()); e != nil {
		return e
	}
	f, e := os.Open(*binary)
	if e != nil {
		return e
	}
	defer f.Close()
	if e = remoteupdate.VerifyBinary(f, m); e != nil {
		return e
	}
	if _, e = f.Seek(0, 0); e != nil {
		return e
	}
	header := base64.StdEncoding.EncodeToString(b)
	fmt.Println("Sending signed release over USB…")
	b, e = request("POST", "/v1/prepare", f, header, m.Bytes)
	if e != nil {
		return e
	}
	var staged struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(b, &staged) != nil || staged.ID == "" {
		return fmt.Errorf("missing staged ID")
	}
	if *stageOnly {
		fmt.Println("Signed update staged without installation:", staged.ID)
		return nil
	}
	body, _ := json.Marshal(map[string]string{"id": staged.ID})
	if _, e = request("POST", "/v1/apply", strings.NewReader(string(body)), "", 0); e != nil {
		return e
	}
	fmt.Println("Waiting for Windows installation: automatic if locally enabled, otherwise administrator confirmation. USB will disconnect during installation.")
	last := ""
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("upgrade outcome not confirmed before timeout; inspect Windows developer status")
		case <-ticker.C:
			b, e = request("GET", "/v1/status", nil, "", 0)
			if e != nil {
				if last != "reconnecting" {
					fmt.Println("Waiting for USB reconnection…")
					last = "reconnecting"
				}
				continue
			}
			var state updateObservation
			if json.Unmarshal(b, &state) != nil {
				continue
			}
			if state.Update.ID != staged.ID {
				return fmt.Errorf("update job changed")
			}
			if state.Update.Status != last {
				fmt.Println(state.Update.Status, state.Update.Detail)
				last = state.Update.Status
			}
			done, outcomeErr := classifyUpdateOutcome(state, m.Version)
			if outcomeErr != nil {
				return outcomeErr
			}
			if done {
				fmt.Println("New version confirmed:", state.Version)
				return nil
			}
		}
	}
}

func discoverUSB() ([]byte, error) {
	dialer := &net.Dialer{Control: usbroute.Control, Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("10.6.9.2")}}
	tr := &http.Transport{Proxy: nil, DialContext: dialer.DialContext}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect refused") }}
	resp, err := c.Get("http://10.6.9.1:10690/maintenance/connection")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("USB developer discovery unavailable (%d)", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil {
		return nil, err
	}
	if len(b) > 4096 {
		return nil, fmt.Errorf("discovery response too large")
	}
	return b, nil
}
