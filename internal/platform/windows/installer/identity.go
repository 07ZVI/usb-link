package installer

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// InterfaceNumber accepts exact Apple composite interface IDs only.
func InterfaceNumber(id string) (int, bool) {
	parts := strings.Split(strings.ToUpper(id), `\`)
	if len(parts) != 3 || parts[0] != "USB" {
		return 0, false
	}
	hw := parts[1]
	for n := 0; n < 4; n++ {
		base := fmt.Sprintf("VID_05AC&PID_1903&MI_%02X", n)
		if hw == base {
			return n, true
		}
	}
	return 0, false
}
func MatchFields(vid, pid, mi, target, button string, n int) bool {
	return strings.EqualFold(strings.TrimSpace(vid), "05AC") && strings.EqualFold(strings.TrimSpace(pid), "1903") && strings.EqualFold(strings.TrimSpace(mi), fmt.Sprintf("%02X", n)) && strings.HasPrefix(strings.ToLower(strings.TrimSpace(target)), "winusb") && button == "Extract Files" && (n == 0 || n == 1)
}

var deviceIDLine = regexp.MustCompile(`(?im)^DeviceID\s*=\s*"([^"\r\n]+)"\s*\r?$`)

// libwdi writes its INF as UTF-16LE with a BOM. Decode for inspection only;
// the original signed file is passed to Windows without modifying its bytes.
func decodeINF(b []byte) (string, error) {
	if len(b) == 0 || len(b) > 1024*1024 {
		return "", fmt.Errorf("invalid INF size: %d", len(b))
	}
	var s string
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		b = b[2:]
		if len(b)%2 != 0 {
			return "", fmt.Errorf("truncated UTF-16LE INF")
		}
		units := make([]uint16, len(b)/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(b[i*2:])
		}
		for i := 0; i < len(units); i++ {
			u := units[i]
			if u >= 0xd800 && u <= 0xdbff {
				if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
					return "", fmt.Errorf("unpaired UTF-16 surrogate in INF")
				}
				i++
			} else if u >= 0xdc00 && u <= 0xdfff {
				return "", fmt.Errorf("unpaired UTF-16 surrogate in INF")
			}
		}
		s = string(utf16.Decode(units))
	} else {
		if !utf8.Valid(b) {
			return "", fmt.Errorf("unsupported INF encoding")
		}
		s = strings.TrimPrefix(string(b), "\ufeff")
	}
	if strings.ContainsRune(s, 0) {
		return "", fmt.Errorf("NUL in decoded INF; missing or unsupported encoding marker")
	}
	return s, nil
}

func ValidateINF(b []byte, n int) error {
	if n != 0 && n != 1 {
		return fmt.Errorf("not a permitted first-group interface")
	}
	s, err := decodeINF(b)
	if err != nil {
		return err
	}
	want := fmt.Sprintf("VID_05AC&PID_1903&MI_%02X", n)
	matches := deviceIDLine.FindAllStringSubmatch(s, -1)
	if len(matches) != 1 || matches[0][1] != want {
		return fmt.Errorf("generated INF target mismatch: want %s, DeviceID declarations=%v; refuse binding", want, matches)
	}
	lower := strings.ToLower(s)
	if !strings.Contains(lower, "include = winusb.inf") || !strings.Contains(lower, "servicebinary = %12%\\winusb.sys") {
		return fmt.Errorf("generated INF is not expected inbox WinUSB template")
	}
	return nil
}
