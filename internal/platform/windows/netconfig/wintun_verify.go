package netconfig

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"strings"
)

// Only the local DLL name used by the loader is admitted, never a device path,
// alternate stream, UNC path or a path which Win32 silently normalizes.
func wintunLocalPathParts(path string) ([]string, error) {
	if len(path) < 13 || len(path) > 4096 || path[1:3] != ":\\" || !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) || strings.ContainsAny(path[3:], ":/\x00*?\"<>|") {
		return nil, errors.New("WINTUN_LOCAL_PATH_INVALID")
	}
	parts := strings.Split(path[3:], "\\")
	if len(parts) < 1 || len(parts) > 64 || !strings.EqualFold(parts[len(parts)-1], "wintun.dll") {
		return nil, errors.New("WINTUN_LOCAL_PATH_INVALID")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part || strings.HasSuffix(part, ".") {
			return nil, errors.New("WINTUN_LOCAL_PATH_INVALID")
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9' {
			return nil, errors.New("WINTUN_LOCAL_PATH_INVALID")
		}
	}
	return parts, nil
}

// This examines only the primary signer certificate returned by the successful
// WinVerifyTrust invocation. It does not substitute Go's trust-chain policy for
// Windows' Authenticode policy. Duplicate CNs are ambiguous and rejected.
func wintunPublisherCertificate(der []byte) error {
	if len(der) == 0 || len(der) > 128*1024 {
		return errors.New("WINTUN_SIGNER_CERTIFICATE_INVALID")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return errors.New("WINTUN_SIGNER_CERTIFICATE_INVALID")
	}
	var subject asn1.RawValue
	if rest, err := asn1.Unmarshal(cert.RawSubject, &subject); err != nil || len(rest) != 0 || subject.Tag != asn1.TagSequence {
		return errors.New("WINTUN_SIGNER_CERTIFICATE_INVALID")
	}
	cnCount := 0
	for _, name := range cert.Subject.Names {
		if name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) {
			value, ok := name.Value.(string)
			if !ok || !strings.EqualFold(value, "WireGuard LLC") {
				return errors.New("WINTUN_SIGNER_NOT_WIREGUARD")
			}
			cnCount++
		}
	}
	if cnCount != 1 {
		return errors.New("WINTUN_SIGNER_NOT_WIREGUARD")
	}
	return nil
}
