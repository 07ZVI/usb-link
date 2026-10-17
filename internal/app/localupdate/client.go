//go:build usblink_local_remote

// Package localupdate provides an explicitly invoked Mac USB installation client.
package localupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"suhang/usbnet/internal/transport/usbroute"
	"time"
)

const endpoint = "https://10.6.9.1:47775"
const discoveryURL = "http://10.6.9.1:10690/maintenance/connection"
const responseLimit = 64 * 1024

type invitation struct {
	URLs  []string `json:"urls"`
	Pin   string   `json:"certificate_sha256"`
	Token string   `json:"token"`
}

func decodeInvitation(data []byte) (invitation, error) {
	var inv invitation
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	var extra any
	if len(data) > 4096 || d.Decode(&inv) != nil || d.Decode(&extra) != io.EOF || len(inv.URLs) != 1 || inv.URLs[0] != endpoint {
		return inv, fmt.Errorf("fixed USB IPv4 invitation required")
	}
	for _, value := range []string{inv.Pin, inv.Token} {
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != 32 || hex.EncodeToString(b) != value {
			return invitation{}, fmt.Errorf("invalid USB credentials")
		}
	}
	return inv, nil
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("control response too large")
	}
	return b, nil
}

func usbTransport(address string, tlsConfig *tls.Config) *http.Transport {
	dialer := &net.Dialer{Control: usbroute.Control, Timeout: 5 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.IPv4(10, 6, 9, 2)}}
	return &http.Transport{Proxy: nil, MaxConnsPerHost: 1, TLSClientConfig: tlsConfig,
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if target != address || (network != "tcp" && network != "tcp4") {
				return nil, fmt.Errorf("non-USB destination refused")
			}
			return dialer.DialContext(ctx, "tcp4", target)
		}}
}

func noRedirect(*http.Request, []*http.Request) error { return fmt.Errorf("redirect refused") }

func pinnedTLS(pin string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13,
		// The invitation pins the exact self-signed certificate instead of a public CA.
		InsecureSkipVerify: true,
		VerifyConnection: func(c tls.ConnectionState) error {
			if c.Version < tls.VersionTLS13 || len(c.PeerCertificates) == 0 {
				return fmt.Errorf("TLS 1.3 server certificate required")
			}
			sum := sha256.Sum256(c.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(pin)) != 1 {
				return fmt.Errorf("Windows certificate identity changed")
			}
			return nil
		}}
}

func discover(ctx context.Context) ([]byte, error) {
	tr := usbTransport("10.6.9.1:10690", nil)
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 8 * time.Second, CheckRedirect: noRedirect}
	q, _ := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	r, err := c.Do(q)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("USB push discovery unavailable (%d)", r.StatusCode)
	}
	return readBounded(r.Body, 4096)
}

type client struct {
	http  *http.Client
	token string
}

func newClient(inv invitation) (*client, func()) {
	tr := usbTransport("10.6.9.1:47775", pinnedTLS(inv.Pin))
	return &client{http: &http.Client{Transport: tr, Timeout: 3 * time.Minute, CheckRedirect: noRedirect}, token: inv.Token}, tr.CloseIdleConnections
}

func (c *client) request(ctx context.Context, method, path string, body io.Reader, manifest string, length int64) ([]byte, error) {
	if !(method == "GET" && path == "/v1/status" || method == "POST" && (path == "/v1/prepare" || path == "/v1/apply" || path == "/v1/cancel")) {
		return nil, fmt.Errorf("unsupported USB push action")
	}
	q, err := http.NewRequestWithContext(ctx, method, endpoint+path, body)
	if err != nil {
		return nil, err
	}
	q.Header.Set("Authorization", "Bearer "+c.token)
	if manifest != "" {
		q.Header.Set("X-Suhang-Release", manifest)
		q.ContentLength = length
	}
	r, err := c.http.Do(q)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	b, err := readBounded(r.Body, responseLimit)
	if err != nil {
		return nil, err
	}
	// Only report fixed classifications; a remote body can reflect credentials.
	if r.StatusCode/100 != 2 {
		return nil, fmt.Errorf("USB push request rejected (%d)%s", r.StatusCode, rejectionReason(b))
	}
	return b, nil
}

func rejectionReason(body []byte) string {
	message := strings.TrimSpace(string(body))
	message = strings.TrimPrefix(message, "staging failed: ")
	for _, code := range []string{
		"LOCAL_REMOTE_NOT_ACTIVE", "LOCAL_REMOTE_USB_REVOKED", "LOCAL_REMOTE_JOB_PENDING",
		"LOCAL_REMOTE_INSTALL_RECOVERY_REQUIRED", "LOCAL_REMOTE_STAGED_BYTES_RECOVERY_REQUIRED",
		"LOCAL_REMOTE_STAGED_DIRECTORY_NOT_EMPTY", "LOCAL_REMOTE_STAGED_DIRECTORY_REMAINS", "LOCAL_REMOTE_CLEANUP_PROCESS_UNPROVEN",
		"LOCAL_REMOTE_CORE_CHANGED", "LOCAL_REMOTE_USER_NOT_LOGGED_ON", "LOCAL_REMOTE_CONSENT_MISSING",
		"LOCAL_REMOTE_CONSENT_CHANGED", "CORE_FILE_PROTECTION_UNPROVEN", "CORE_FILE_UNREADABLE",
	} {
		if message == code || strings.HasPrefix(message, code+": ") {
			return ": " + code
		}
	}
	for _, reason := range []string{"Access is denied.", "The directory is not empty.",
		"The system cannot find the file specified.", "The system cannot find the path specified.",
		"The process cannot access the file because it is being used by another process.",
		"release length or SHA256 mismatch"} {
		if message == reason || strings.HasSuffix(message, ": "+reason) {
			return ": " + reason
		}
	}
	if strings.HasPrefix(message, "upgrade mutex ") {
		return ": upgrade mutex unavailable"
	}
	return ""
}
