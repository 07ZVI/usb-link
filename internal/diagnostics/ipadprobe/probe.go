// Package ipadprobe checks an already-paired iPad over USB. It does not pair,
// change settings, open file services, or create a system network interface.
package ipadprobe

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"howett.net/plist"
)

const serviceName = "com.apple.internal.devicecompute.CoreDeviceProxy"
const maxFrame = 512 * 1024

type Result struct {
	Protocol          string `json:"protocol"`
	Version           string `json:"version"`
	Started           string `json:"started_utc"`
	Stage             string `json:"stage"`
	Status            string `json:"status"`
	ErrorCode         string `json:"error_code,omitempty"`
	USBDeviceCount    int    `json:"usb_device_count"`
	ProductType       string `json:"product_type,omitempty"`
	ProductVersion    string `json:"product_version,omitempty"`
	BuildVersion      string `json:"build_version,omitempty"`
	PairedSession     bool   `json:"paired_session"`
	CertificatePinned bool   `json:"certificate_pinned"`
	TunnelHandshake   bool   `json:"tunnel_handshake"`
	TunnelMTU         int    `json:"tunnel_mtu,omitempty"`
	EchoReplies       int    `json:"echo_replies"`
	RSDTCPReachable   bool   `json:"rsd_tcp_reachable"`
	MoonlightVerified bool   `json:"moonlight_verified"`
	BandwidthMeasured bool   `json:"bandwidth_measured"`
}

func failure(code string) error { return errors.New(code) }
func number(v any) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case int64:
		if n >= 0 {
			return uint64(n)
		}
	case int:
		if n >= 0 {
			return uint64(n)
		}
	}
	return 0
}
func text(v any) string { s, _ := v.(string); return s }
func flag(v any) bool   { b, _ := v.(bool); return b }
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return failure("WRITE_FAILED")
		}
		if n <= 0 || n > len(b) {
			return failure("SHORT_WRITE")
		}
		b = b[n:]
	}
	return nil
}
func readPlist(r io.Reader, mux bool) (map[string]any, error) {
	size := 4
	if mux {
		size = 16
	}
	h := make([]byte, size)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, failure("READ_HEADER_FAILED")
	}
	n := int(binary.BigEndian.Uint32(h))
	if mux {
		n = int(binary.LittleEndian.Uint32(h)) - 16
		if binary.LittleEndian.Uint32(h[4:]) != 1 || binary.LittleEndian.Uint32(h[8:]) != 8 || binary.LittleEndian.Uint32(h[12:]) != 1 {
			return nil, failure("INVALID_MUX_HEADER")
		}
	}
	if n <= 0 || n > maxFrame {
		return nil, failure("INVALID_FRAME_SIZE")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, failure("READ_BODY_FAILED")
	}
	var d map[string]any
	if _, err := plist.Unmarshal(b, &d); err != nil {
		return nil, failure("INVALID_PLIST")
	}
	return d, nil
}
func sendPlist(w io.Writer, d map[string]any, mux bool) error {
	b, err := plist.Marshal(d, plist.XMLFormat)
	if err != nil {
		return failure("ENCODE_FAILED")
	}
	if len(b) > maxFrame {
		return failure("INVALID_FRAME_SIZE")
	}
	var h []byte
	if mux {
		h = make([]byte, 16)
		binary.LittleEndian.PutUint32(h, uint32(len(b)+16))
		binary.LittleEndian.PutUint32(h[4:], 1)
		binary.LittleEndian.PutUint32(h[8:], 8)
		binary.LittleEndian.PutUint32(h[12:], 1)
	} else {
		h = make([]byte, 4)
		binary.BigEndian.PutUint32(h, uint32(len(b)))
	}
	return writeAll(w, append(h, b...))
}
func deadline(c net.Conn, ctx context.Context, span time.Duration) {
	d := time.Now().Add(span)
	if end, ok := ctx.Deadline(); ok && end.Before(d) {
		d = end
	}
	c.SetDeadline(d)
}
func muxRequest(ctx context.Context, kind string, args map[string]any) (net.Conn, map[string]any, error) {
	c, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", "127.0.0.1:27015")
	if err != nil {
		return nil, nil, failure("APPLE_USB_SERVICE_UNAVAILABLE")
	}
	deadline(c, ctx, 6*time.Second)
	d := map[string]any{"MessageType": kind, "ClientVersionString": "Suhang-iPad-Probe-0.1.0", "ProgName": "Suhang-iPad-Probe", "kLibUSBMuxVersion": uint64(3)}
	for k, v := range args {
		d[k] = v
	}
	if err = sendPlist(c, d, true); err != nil {
		c.Close()
		return nil, nil, err
	}
	reply, err := readPlist(c, true)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	if text(reply["MessageType"]) == "Result" && number(reply["Number"]) != 0 {
		c.Close()
		return nil, nil, failure("MUX_REQUEST_REJECTED")
	}
	return c, reply, nil
}
func connect(ctx context.Context, id, port uint64) (net.Conn, error) {
	if id == 0 || id > 0xffffffff || port == 0 || port > 65535 {
		return nil, failure("INVALID_DEVICE_OR_PORT")
	}
	p := (port&255)<<8 | port>>8
	c, d, err := muxRequest(ctx, "Connect", map[string]any{"DeviceID": id, "PortNumber": p})
	if err != nil {
		return nil, err
	}
	if text(d["MessageType"]) != "Result" || number(d["Number"]) != 0 {
		c.Close()
		return nil, failure("MUX_CONNECT_REJECTED")
	}
	return c, nil
}
func request(ctx context.Context, c net.Conn, kind string, args map[string]any) (map[string]any, error) {
	deadline(c, ctx, 6*time.Second)
	d := map[string]any{"Request": kind, "Label": "Suhang-iPad-Probe"}
	for k, v := range args {
		d[k] = v
	}
	if err := sendPlist(c, d, false); err != nil {
		return nil, err
	}
	reply, err := readPlist(c, false)
	if err != nil {
		return nil, err
	}
	if s := text(reply["Error"]); s != "" {
		switch s {
		case "InvalidHostID", "InvalidPairRecord", "PairingDialogResponsePending", "UserDeniedPairing", "PasswordProtected", "DeviceLocked", "InvalidService", "MissingPairRecord", "SessionInactive", "InvalidSessionID":
			return nil, failure(s)
		default:
			return nil, failure("LOCKDOWN_REQUEST_REJECTED")
		}
	}
	if got := text(reply["Request"]); got != "" && got != kind {
		return nil, failure("LOCKDOWN_RESPONSE_MISMATCH")
	}
	return reply, nil
}
func pinnedTLS(ctx context.Context, c net.Conn, pair map[string]any) (net.Conn, error) {
	cert, _ := pair["HostCertificate"].([]byte)
	key, _ := pair["HostPrivateKey"].([]byte)
	device, _ := pair["DeviceCertificate"].([]byte)
	if len(cert) == 0 || len(key) == 0 || len(device) == 0 {
		return nil, failure("PAIR_CERTIFICATE_MISSING")
	}
	cc, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, failure("PAIR_CLIENT_CERTIFICATE_INVALID")
	}
	block, _ := pem.Decode(device)
	if block == nil {
		return nil, failure("PAIR_DEVICE_CERTIFICATE_INVALID")
	}
	expected, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, failure("PAIR_DEVICE_CERTIFICATE_INVALID")
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cc},
		// Pairing certificates have no public DNS name. This replaces DNS
		// verification with mandatory exact device-certificate pinning.
		InsecureSkipVerify: true,
		VerifyConnection: func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 || !bytes.Equal(s.PeerCertificates[0].Raw, expected.Raw) {
				return failure("DEVICE_CERTIFICATE_PIN_MISMATCH")
			}
			return nil
		},
	}
	t := tls.Client(c, cfg)
	deadline(t, ctx, 6*time.Second)
	if err = t.HandshakeContext(ctx); err != nil {
		return nil, failure("PAIRED_TLS_HANDSHAKE_FAILED")
	}
	return t, nil
}

// Run uses the existing pairing identity only in memory. No credentials,
// device identifier, raw service responses or personal files are logged.
func Run(ctx context.Context, version string) Result {
	r := Result{Protocol: "SUHANG-IPAD-USB-PROBE/1", Version: version, Started: time.Now().UTC().Format(time.RFC3339), Stage: "USB_ENUMERATION", Status: "FAILED"}
	if err := run(ctx, &r); err != nil {
		r.ErrorCode = err.Error()
	}
	return r
}
func run(ctx context.Context, r *Result) error {
	c, d, err := muxRequest(ctx, "ListDevices", nil)
	if err != nil {
		return err
	}
	c.Close()
	var selected map[string]any
	list, _ := d["DeviceList"].([]any)
	for _, v := range list {
		entry, _ := v.(map[string]any)
		props, _ := entry["Properties"].(map[string]any)
		if text(props["ConnectionType"]) == "USB" {
			r.USBDeviceCount++
			selected = entry
		}
	}
	if r.USBDeviceCount != 1 {
		return failure("CONNECT_EXACTLY_ONE_APPLE_USB_DEVICE")
	}
	props, _ := selected["Properties"].(map[string]any)
	id := number(selected["DeviceID"])
	if id == 0 {
		id = number(props["DeviceID"])
	}
	serial := text(props["SerialNumber"])
	if serial == "" {
		return failure("DEVICE_IDENTIFIER_MISSING")
	}
	r.Stage = "LOCKDOWN_METADATA"
	lc, err := connect(ctx, id, 62078)
	if err != nil {
		return err
	}
	rawLockdown := lc
	defer rawLockdown.Close()
	q, err := request(ctx, lc, "QueryType", nil)
	if err != nil {
		return err
	}
	if text(q["Type"]) != "com.apple.mobile.lockdown" {
		return failure("UNEXPECTED_LOCKDOWN_PEER")
	}
	for _, item := range []struct {
		key string
		out *string
	}{{"ProductType", &r.ProductType}, {"ProductVersion", &r.ProductVersion}, {"BuildVersion", &r.BuildVersion}} {
		q, err = request(ctx, lc, "GetValue", map[string]any{"Key": item.key})
		if err != nil {
			return err
		}
		*item.out = text(q["Value"])
		if len(*item.out) > 64 {
			*item.out = "INVALID"
			return failure("INVALID_PRODUCT_METADATA")
		}
	}
	if !strings.HasPrefix(r.ProductType, "iPad") {
		return failure("CONNECTED_DEVICE_IS_NOT_IPAD")
	}
	r.Stage = "EXISTING_PAIRING"
	pc, pd, err := muxRequest(ctx, "ReadPairRecord", map[string]any{"PairRecordID": serial})
	if err != nil {
		return failure("EXISTING_PAIR_RECORD_UNAVAILABLE")
	}
	pc.Close()
	pairData, _ := pd["PairRecordData"].([]byte)
	if len(pairData) == 0 || len(pairData) > maxFrame {
		return failure("EXISTING_PAIR_RECORD_UNAVAILABLE")
	}
	var pair map[string]any
	if _, err = plist.Unmarshal(pairData, &pair); err != nil {
		return failure("EXISTING_PAIR_RECORD_INVALID")
	}
	host, buid := text(pair["HostID"]), text(pair["SystemBUID"])
	if host != "" && buid == "" {
		bc, bd, er := muxRequest(ctx, "ReadBUID", nil)
		if er != nil {
			return failure("PAIR_IDENTITY_INCOMPLETE")
		}
		bc.Close()
		buid = text(bd["BUID"])
	}
	if host == "" || buid == "" {
		return failure("PAIR_IDENTITY_INCOMPLETE")
	}
	q, err = request(ctx, lc, "StartSession", map[string]any{"HostID": host, "SystemBUID": buid})
	if err != nil {
		return err
	}
	sid := text(q["SessionID"])
	if sid == "" || !flag(q["EnableSessionSSL"]) {
		return failure("PAIRED_TLS_SESSION_REQUIRED")
	}
	lc, err = pinnedTLS(ctx, lc, pair)
	if err != nil {
		return err
	}
	r.PairedSession = true
	r.CertificatePinned = true
	defer func() { request(ctx, lc, "StopSession", map[string]any{"SessionID": sid}) }()
	r.Stage = "COREDEVICE_SERVICE"
	attr, err := request(ctx, lc, "StartService", map[string]any{"Service": serviceName})
	if err != nil {
		return err
	}
	sc, err := connect(ctx, id, number(attr["Port"]))
	if err != nil {
		return err
	}
	rawService := sc
	defer rawService.Close()
	if flag(attr["EnableServiceSSL"]) {
		sc, err = pinnedTLS(ctx, sc, pair)
		if err != nil {
			return err
		}
	}
	// Credentials never leave memory, and only the CoreDevice service is opened.
	r.Stage = "TUNNEL_HANDSHAKE"
	deadline(sc, ctx, 6*time.Second)
	hello, _ := json.Marshal(map[string]any{"type": "clientHandshakeRequest", "mtu": 16000})
	frame := append([]byte("CDTunnel"), byte(len(hello)>>8), byte(len(hello)))
	frame = append(frame, hello...)
	if err = writeAll(sc, frame); err != nil {
		return err
	}
	h := make([]byte, 10)
	if _, err = io.ReadFull(sc, h); err != nil {
		return failure("TUNNEL_HANDSHAKE_READ_FAILED")
	}
	if string(h[:8]) != "CDTunnel" {
		return failure("TUNNEL_MAGIC_MISMATCH")
	}
	n := int(binary.BigEndian.Uint16(h[8:]))
	if n == 0 || n > 32768 {
		return failure("TUNNEL_HANDSHAKE_SIZE_INVALID")
	}
	body := make([]byte, n)
	if _, err = io.ReadFull(sc, body); err != nil {
		return failure("TUNNEL_HANDSHAKE_READ_FAILED")
	}
	var hs struct {
		Client struct {
			Address string `json:"address"`
			MTU     int    `json:"mtu"`
		} `json:"clientParameters"`
		Server string `json:"serverAddress"`
		Port   int    `json:"serverRSDPort"`
	}
	if json.Unmarshal(body, &hs) != nil {
		return failure("TUNNEL_HANDSHAKE_JSON_INVALID")
	}
	local, remote := net.ParseIP(hs.Client.Address), net.ParseIP(hs.Server)
	if local == nil || remote == nil || local.To4() != nil || remote.To4() != nil || local.IsUnspecified() || remote.IsUnspecified() || local.Equal(remote) || hs.Client.MTU < 1280 || hs.Client.MTU > 65535 || hs.Port < 1 || hs.Port > 65535 {
		return failure("TUNNEL_PARAMETERS_INVALID")
	}
	r.TunnelHandshake = true
	r.TunnelMTU = hs.Client.MTU
	r.Stage = "RAW_IPV6_PROBE"
	nonce := make([]byte, 24)
	if _, err = rand.Read(nonce); err != nil {
		return failure("RANDOM_FAILED")
	}
	echo := make([]byte, 8+len(nonce))
	echo[0] = 128
	copy(echo[4:8], nonce[:4])
	copy(echo[8:], nonce)
	deadline(sc, ctx, 3*time.Second)
	if err = writeAll(sc, ipv6Packet(local, remote, 58, echo)); err != nil {
		return err
	}
	syn := make([]byte, 20)
	binary.BigEndian.PutUint16(syn, 45001)
	binary.BigEndian.PutUint16(syn[2:], uint16(hs.Port))
	copy(syn[4:8], nonce[4:8])
	syn[12] = 0x50
	syn[13] = 2
	binary.BigEndian.PutUint16(syn[14:], 4096)
	deadline(sc, ctx, 3*time.Second)
	if err = writeAll(sc, ipv6Packet(local, remote, 6, syn)); err != nil {
		return err
	}
	// Send both probes before reading. A timeout can interrupt a TCP frame;
	// never restart framing after that partial read has been discarded.
	for i := 0; i < 64; i++ {
		p, er := readIPv6(sc, hs.Client.MTU)
		if er != nil {
			break
		}
		if validEchoReply(p, local, remote, echo) {
			r.EchoReplies = 1
		}
		if !r.RSDTCPReachable && validSYNACK(p, local, remote, syn) {
			r.RSDTCPReachable = true
			rst := make([]byte, 20)
			copy(rst[:4], syn[:4])
			copy(rst[4:8], p[48:52])
			binary.BigEndian.PutUint32(rst[8:], binary.BigEndian.Uint32(p[44:48])+1)
			rst[12] = 0x50
			rst[13] = 0x14
			writeAll(sc, ipv6Packet(local, remote, 6, rst))
		}
		if r.RSDTCPReachable && r.EchoReplies > 0 {
			break
		}
	}
	r.Stage = "COMPLETE"
	r.Status = "TUNNEL_HANDSHAKE_ONLY"
	if r.RSDTCPReachable || r.EchoReplies > 0 {
		r.Status = "RAW_IPV6_ROUNDTRIP_CONFIRMED"
	}
	return nil
}
func checksum(b []byte) uint16 {
	var n uint32
	for len(b) >= 2 {
		n += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		n += uint32(b[0]) << 8
	}
	for n>>16 != 0 {
		n = (n & 65535) + (n >> 16)
	}
	return ^uint16(n)
}
func transportChecksum(src, dst net.IP, next byte, p []byte) uint16 {
	h := make([]byte, 40)
	copy(h, src.To16())
	copy(h[16:], dst.To16())
	binary.BigEndian.PutUint32(h[32:], uint32(len(p)))
	h[39] = next
	return checksum(append(h, p...))
}
func ipv6Packet(src, dst net.IP, next byte, payload []byte) []byte {
	p := append([]byte(nil), payload...)
	off := 2
	if next == 6 {
		off = 16
	}
	p[off] = 0
	p[off+1] = 0
	binary.BigEndian.PutUint16(p[off:], transportChecksum(src, dst, next, p))
	b := make([]byte, 40)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(len(p)))
	b[6] = next
	b[7] = 64
	copy(b[8:24], src.To16())
	copy(b[24:], dst.To16())
	return append(b, p...)
}
func readIPv6(r io.Reader, mtu int) ([]byte, error) {
	h := make([]byte, 40)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[4:]))
	if h[0]>>4 != 6 || n+40 > mtu {
		return nil, failure("INVALID_IPV6_FRAME")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(h, body...), nil
}
func validReply(p []byte, local, remote net.IP, next byte, min int) bool {
	return len(p) >= 40+min && p[0]>>4 == 6 && int(binary.BigEndian.Uint16(p[4:])) == len(p)-40 && p[6] == next && bytes.Equal(p[8:24], remote.To16()) && bytes.Equal(p[24:40], local.To16()) && transportChecksum(remote, local, next, p[40:]) == 0
}
func validEchoReply(p []byte, local, remote net.IP, echo []byte) bool {
	return validReply(p, local, remote, 58, len(echo)) && len(p) == 40+len(echo) && p[40] == 129 && p[41] == 0 && bytes.Equal(p[44:], echo[4:])
}
func validSYNACK(p []byte, local, remote net.IP, syn []byte) bool {
	return validReply(p, local, remote, 6, 20) && p[52]>>4 >= 5 && int(p[52]>>4)*4 <= len(p)-40 && p[53]&0x17 == 0x12 && bytes.Equal(p[40:42], syn[2:4]) && bytes.Equal(p[42:44], syn[:2]) && binary.BigEndian.Uint32(p[48:52]) == binary.BigEndian.Uint32(syn[4:8])+1
}
